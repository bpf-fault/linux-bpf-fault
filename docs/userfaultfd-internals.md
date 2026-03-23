# Userfaultfd Internals: Reference for BPF Fault Development

This document describes how userfaultfd is implemented in the Linux kernel,
focusing on the fault paths that bpf_fault aims to replace: **MISSING** and
**write-protect (WP)** for anonymous pages, and **MISSING** and **MINOR** for
shmem pages. It traces the complete lifecycle from registration through fault
delivery, blocking, and resolution.

Based on the v6.17 kernel tree with bpf_fault patches applied.

---

## Table of Contents

1. [Data Structures](#1-data-structures)
2. [Lifecycle: Creation and API Handshake](#2-lifecycle-creation-and-api-handshake)
3. [Registration (UFFDIO_REGISTER)](#3-registration-uffdio_register)
4. [VMA Flags and PTE Bits](#4-vma-flags-and-pte-bits)
5. [Anonymous MISSING Fault Path](#5-anonymous-missing-fault-path)
6. [Anonymous Write-Protect Fault Path](#6-anonymous-write-protect-fault-path)
7. [PTE Markers for uffd-wp](#7-pte-markers-for-uffd-wp)
8. [Shmem MISSING Fault Path](#8-shmem-missing-fault-path)
9. [Shmem MINOR Fault Path](#9-shmem-minor-fault-path)
10. [handle_userfault(): The Blocking Mechanism](#10-handle_userfault-the-blocking-mechanism)
11. [Resolution Ioctls](#11-resolution-ioctls)
12. [Unregistration and Cleanup](#12-unregistration-and-cleanup)
13. [Fork Handling](#13-fork-handling)
14. [Complete Fault Flow Diagrams](#14-complete-fault-flow-diagrams)
15. [Where bpf_fault Currently Hooks In](#15-where-bpf_fault-currently-hooks-in)
16. [Key Differences: bpf_fault vs userfaultfd](#16-key-differences-bpf_fault-vs-userfaultfd)

---

## 1. Data Structures

### 1.1 `struct userfaultfd_ctx` (`include/linux/userfaultfd_k.h:73`)

The per-fd context, created when `userfaultfd(2)` is called:

```c
struct userfaultfd_ctx {
    wait_queue_head_t fault_pending_wqh;   // faults queued, not yet read()
    wait_queue_head_t fault_wqh;           // faults read() but not resolved
    wait_queue_head_t fd_wqh;              // wakes poll()/read() on the uffd fd
    wait_queue_head_t event_wqh;           // non-pagefault events (fork/remap/remove)
    seqcount_spinlock_t refile_seq;        // protects refile from pending -> wqh
    refcount_t refcount;
    unsigned int flags;                    // O_CLOEXEC, O_NONBLOCK, UFFD_USER_MODE_ONLY
    unsigned int features;                 // features enabled via UFFDIO_API
    bool released;                         // true when fd is closed
    struct rw_semaphore map_changing_lock;  // serializes with non-cooperative events
    atomic_t mmap_changing;                // >0 during fork/mremap/munmap
    struct mm_struct *mm;
};
```

**Wait queue architecture (two-queue design):**

The two-queue design separates "pending" faults from "in-flight" faults:

1. A faulting thread adds itself to `fault_pending_wqh` and sleeps.
2. The monitor's `read()` finds the fault in `fault_pending_wqh`, refiles it to
   `fault_wqh`, and returns the `uffd_msg` to userspace.
3. The monitor resolves the fault (via UFFDIO_COPY, etc.), which calls
   `wake_userfault()` to wake matching entries in both queues.

This means a fault is visible to `poll()` only while pending (not yet read).
After `read()`, the fault moves to `fault_wqh` where the faulting thread waits
for resolution.

**Locking order** (IRQs must be disabled for all):
```
fd_wqh.lock
    fault_pending_wqh.lock
        fault_wqh.lock
    event_wqh.lock
```

### 1.2 `struct vm_userfaultfd_ctx` (`include/linux/mm_types.h:696`)

A thin wrapper stored per-VMA:

```c
struct vm_userfaultfd_ctx {
    union {
        struct userfaultfd_ctx *ctx;
        struct bpf_fault_ctx *bpf_ctx;   // CONFIG_BPF_FAULT
    };
};
```

Embedded in `struct vm_area_struct` at line 929. The union means a VMA can have
**either** a userfaultfd context **or** a bpf_fault context, never both.

**Invariant enforced throughout the code:**
```c
VM_WARN_ON_ONCE(!!vma->vm_userfaultfd_ctx.ctx ^ !!(vma->vm_flags & __VM_UFFD_FLAGS));
```
A VMA has a non-NULL ctx if and only if at least one uffd flag is set.

### 1.3 UAPI structures (`include/uapi/linux/userfaultfd.h`)

The fault notification delivered via `read()` on the uffd fd:

```c
struct uffd_msg {
    __u8 event;                  // UFFD_EVENT_PAGEFAULT, _FORK, _REMAP, _REMOVE, _UNMAP
    union {
        struct {
            __u64 flags;         // UFFD_PAGEFAULT_FLAG_WRITE | _WP | _MINOR
            __u64 address;
            union { __u32 ptid; } feat;
        } pagefault;
        // ... fork, remap, remove variants
    } arg;
};
```

Resolution ioctl structures:

| Struct | Fields | Purpose |
|--------|--------|---------|
| `uffdio_copy` | `dst`, `src`, `len`, `mode`, `copy` | Copy user data into faulting pages |
| `uffdio_zeropage` | `range`, `mode`, `zeropage` | Map zero pages |
| `uffdio_writeprotect` | `range`, `mode` | Set/clear write protection |
| `uffdio_continue` | `range`, `mode`, `mapped` | Map existing page-cache page (minor faults) |

---

## 2. Lifecycle: Creation and API Handshake

### Creation (`fs/userfaultfd.c:2112`)

Two paths, both calling `new_userfaultfd(flags)`:
- `userfaultfd(2)` syscall (line 2177)
- `/dev/userfaultfd` ioctl `USERFAULTFD_IOC_NEW` (line 2185)

`new_userfaultfd()` allocates a `userfaultfd_ctx` from a slab cache (with
`init_once_userfaultfd_ctx` as constructor to initialize wait queues), sets
`refcount=1`, `features=0`, `released=false`, pins the mm with `mmgrab()`, and
returns a file descriptor backed by `userfaultfd_fops`.

### API handshake — `UFFDIO_API` (`fs/userfaultfd.c:1953`)

Must be the first ioctl. Uses `cmpxchg(&ctx->features, 0, ctx_features)` to
atomically set features exactly once. `UFFD_FEATURE_INITIALIZED` (bit 31) is
an internal bit marking handshake completion — all other ioctls check this.

Key features relevant to bpf_fault replacement:
- `UFFD_FEATURE_PAGEFAULT_FLAG_WP` — report WP status in fault messages
- `UFFD_FEATURE_MINOR_SHMEM` — enable minor fault handling for shmem
- `UFFD_FEATURE_WP_UNPOPULATED` — allow WP on none pages (installs PTE markers)
- `UFFD_FEATURE_WP_ASYNC` — clear uffd-wp silently instead of notifying

---

## 3. Registration (UFFDIO_REGISTER)

### `userfaultfd_register()` (`fs/userfaultfd.c:1242`)

**Input:** `struct uffdio_register` with `range` and `mode` (bitmask of
`UFFDIO_REGISTER_MODE_MISSING`, `_WP`, `_MINOR`).

**Validation (under mmap_write_lock):**
1. Mode bits map to VM flags: `MODE_MISSING → VM_UFFD_MISSING`,
   `MODE_WP → VM_UFFD_WP`, `MODE_MINOR → VM_UFFD_MINOR`.
2. Each VMA must pass `vma_can_userfault()` — must be anonymous, shmem, or
   hugetlb; MINOR only for shmem/hugetlb; VM_MAYWRITE required.
3. A VMA can only belong to **one** userfaultfd at a time (returns `-EBUSY` if
   a different ctx is already set).

**Registration (via `userfaultfd_register_range()` in `mm/userfaultfd.c:1971`):**

For each VMA in the range:
1. Compute `new_flags = (vma->vm_flags & ~__VM_UFFD_FLAGS) | vm_flags`
2. Call `vma_modify_flags_uffd()` — handles VMA splitting/merging
3. Call `userfaultfd_set_ctx(vma, ctx, vm_flags)`:
   - Takes VMA write lock
   - Sets `vma->vm_userfaultfd_ctx.ctx = ctx`
   - Calls `vm_flags_reset()` with new flags
   - Recalculates `vm_page_prot` for shared mappings when WP changes

**Output:** Reports available ioctls back to userspace (e.g., `UFFDIO_COPY`,
`UFFDIO_WRITEPROTECT`, `UFFDIO_CONTINUE` depending on registration mode).

---

## 4. VMA Flags and PTE Bits

### VMA flags (`include/linux/mm.h`)

| Flag | Value | Purpose |
|------|-------|---------|
| `VM_UFFD_MISSING` | `0x200` | Trap faults on pages with no PTE |
| `VM_UFFD_WP` | `0x1000` | Track write-protection via uffd |
| `VM_UFFD_MINOR` | `BIT(41)` | Trap faults when page exists in cache but isn't mapped |
| `__VM_UFFD_FLAGS` | combined | `VM_UFFD_MISSING \| VM_UFFD_WP \| VM_UFFD_MINOR` |

Also defined in `include/linux/mm.h`:
- `VM_FAULT` defined in `include/linux/mm.h:270` (`VM_UFFD_WP`) — `VM_UFFD_WP = 0x00001000` — also occupies the same bit as `VM_FAULT` which is used to indicate BPF fault support in the bpf_fault patches (via `VM_BPF_FAULT`).

Inline checkers in `include/linux/userfaultfd_k.h:203`:

```c
static inline bool userfaultfd_missing(struct vm_area_struct *vma)
    → vma->vm_flags & VM_UFFD_MISSING

static inline bool userfaultfd_wp(struct vm_area_struct *vma)
    → vma->vm_flags & VM_UFFD_WP

static inline bool userfaultfd_minor(struct vm_area_struct *vma)
    → vma->vm_flags & VM_UFFD_MINOR

static inline bool userfaultfd_armed(struct vm_area_struct *vma)
    → vma->vm_flags & __VM_UFFD_FLAGS

static inline bool userfaultfd_pte_wp(struct vm_area_struct *vma, pte_t pte)
    → userfaultfd_wp(vma) && pte_uffd_wp(pte)
```

### PTE bits for uffd-wp (x86)

Three forms of uffd-wp protection exist, depending on PTE state:

| PTE State | Where uffd-wp bit lives | Accessors |
|-----------|------------------------|-----------|
| **Present** | bit 10 (`_PAGE_UFFD_WP`, software-available bit 2) | `pte_uffd_wp()`, `pte_mkuffd_wp()`, `pte_clear_uffd_wp()` |
| **Swap entry** | bit 2 (`_PAGE_SWP_UFFD_WP`, reuses `_PAGE_USER`) | `pte_swp_uffd_wp()`, `pte_swp_mkuffd_wp()` |
| **PTE marker** | `PTE_MARKER_UFFD_WP` (BIT(0)) in swap offset | `pte_marker_uffd_wp()`, `pte_marker_entry_uffd_wp()` |

**Critical:** `pte_mkuffd_wp()` also **write-protects** the PTE (calls
`pte_wrprotect()`). The uffd-wp bit augments the standard write-protection by
marking it as uffd-managed (rather than COW or permission-based).

Defined in `arch/x86/include/asm/pgtable_types.h:21,34,114` and
`arch/x86/include/asm/pgtable.h:420`.

---

## 5. Anonymous MISSING Fault Path

### Entry: `handle_pte_fault()` (`mm/memory.c:6019`)

```
handle_pte_fault()
  → PTE is none (vmf->pte == NULL)
    → do_pte_missing()                              // line 6063
      → vma_is_anonymous(vma) is true
        → do_anonymous_page()                        // line 5005
```

### `do_anonymous_page()` (`mm/memory.c:5005`)

**Read fault (zero-page path, line 5026):**

```c
if (!(vmf->flags & FAULT_FLAG_WRITE) && !mm_forbids_zeropage(mm)) {
    entry = pte_mkspecial(pfn_pte(my_zero_pfn(vmf->address), vma->vm_page_prot));
    vmf->pte = pte_offset_map_lock(mm, vmf->pmd, vmf->address, &vmf->ptl);
    // ... race checks ...

    if (userfaultfd_missing(vma)) {                 // line 5042
        pte_unmap_unlock(vmf->pte, vmf->ptl);
        return handle_userfault(vmf, VM_UFFD_MISSING);
    }

    // --- bpf_fault hooks here (line 5046) ---

    goto setpte;
}
```

**Write fault (real page allocation, line 5053):**

```c
folio = alloc_anon_folio(vmf);
// ... setup PTE entry ...
vmf->pte = pte_offset_map_lock(...);
// ... race checks ...

if (userfaultfd_missing(vma)) {                     // line 5095
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    folio_put(folio);                               // free the allocated folio
    return handle_userfault(vmf, VM_UFFD_MISSING);
}

// --- bpf_fault hooks here (line 5101) ---
```

**Key detail — uffd-wp marker preservation at `setpte:` (line 5112):**

```c
setpte:
    if (vmf_orig_pte_uffd_wp(vmf))
        entry = pte_mkuffd_wp(entry);
    set_ptes(vma->vm_mm, addr, vmf->pte, entry, nr_pages);
```

When the PTE slot previously held a `PTE_MARKER_UFFD_WP` marker, the
newly-installed PTE inherits the uffd-wp bit. This is how uffd-wp state
survives page population — the marker is replaced by a real PTE that is still
write-protected.

### THP suppression

Both `do_huge_pmd_anonymous_page()` (line 4374) and the allocation path in
`do_anonymous_page()` (line 5405) fall back to single pages when userfaultfd
(or bpf_fault) is armed, because per-page fault fidelity is needed.

---

## 6. Anonymous Write-Protect Fault Path

### Entry: `do_wp_page()` (`mm/memory.c:3921`)

Called from `handle_pte_fault()` at line 6079 when a write fault hits a
non-writable present PTE.

**The uffd-wp check is the first thing `do_wp_page()` does** (line 3929):

```c
if (likely(!unshare)) {
    if (userfaultfd_pte_wp(vma, ptep_get(vmf->pte))) {
        if (!userfaultfd_wp_async(vma)) {
            // Synchronous uffd-wp: block and notify userspace
            pte_unmap_unlock(vmf->pte, vmf->ptl);
            return handle_userfault(vmf, VM_UFFD_WP);   // line 3933
        }
        // Async uffd-wp: silently clear the bit, fall through to COW
        pte = pte_clear_uffd_wp(ptep_get(vmf->pte));    // line 3941
        set_pte_at(vma->vm_mm, vmf->address, vmf->pte, pte);
    }
    // TLB flush for deferred uffd-wp flushes
    if (unlikely(userfaultfd_wp(vmf->vma) &&
                 mm_tlb_flush_pending(vmf->vma->vm_mm)))
        flush_tlb_page(vmf->vma, vmf->address);
}
```

**Two modes:**
1. **Synchronous** (`!wp_async`): Calls `handle_userfault(vmf, VM_UFFD_WP)`,
   which blocks the thread and notifies the monitor. Returns `VM_FAULT_RETRY`.
2. **Async** (`wp_async`): Clears the uffd-wp bit in-place, then falls through
   to normal COW handling. No userspace notification.

### uffd-wp preservation during COW

In `wp_page_copy()` (line 3602), during an unshare operation (not a write),
the uffd-wp bit is preserved on the new copy:

```c
if (unlikely(unshare)) {
    if (pte_uffd_wp(vmf->orig_pte))
        entry = pte_mkuffd_wp(entry);
}
```

For actual writes, the page becomes dirty+writable and uffd-wp is not carried
over (the write resolves the protection).

---

## 7. PTE Markers for uffd-wp

PTE markers are non-present, non-swap PTEs used to store metadata in otherwise
empty page table slots. They use the `SWP_PTE_MARKER` swap type
(`include/linux/swap.h:62`), with marker bits stored in the swap offset field.

### Definitions (`include/linux/swapops.h:403`)

```c
#define PTE_MARKER_UFFD_WP    BIT(0)
#define PTE_MARKER_POISONED   BIT(1)
#define PTE_MARKER_GUARD      BIT(2)
```

Key helpers:
```c
make_pte_marker(PTE_MARKER_UFFD_WP)    // create a swap-like PTE with the marker
is_pte_marker(pte)                      // check if PTE is a marker
pte_marker_get(entry)                   // extract marker bits from swap entry
pte_none_mostly(pte)                    // true for both none PTEs AND PTE markers
```

### When markers are used

`userfaultfd_wp_use_markers()` (`include/linux/userfaultfd_k.h:461`):
- **Always** for file-backed VMAs (shmem/hugetlb) — a none PTE does not mean
  the page doesn't exist (it could be in the page cache), so a marker must be
  installed to remember the wp state.
- For anonymous VMAs, **only** when `WP_UNPOPULATED` is enabled — to protect
  pages that have no backing page yet.

### How markers are installed

`UFFDIO_WRITEPROTECT` ioctl → `mwriteprotect_range()` → `uffd_wp_range()`
→ `change_protection()` → `change_pte_range()` (`mm/mprotect.c:272`):

```
change_pte_range() handles three cases:

1. Present PTE:   pte_mkuffd_wp(pte) / pte_clear_uffd_wp(pte)
2. Swap entry:    pte_swp_mkuffd_wp() / pte_swp_clear_uffd_wp()
3. None PTE:      install make_pte_marker(PTE_MARKER_UFFD_WP)
                  (only when userfaultfd_wp_use_markers(vma) is true)
```

### How markers are handled in the fault path

When a fault hits a PTE marker, it enters `do_swap_page()` (because the marker
looks like a swap entry), which detects it via `is_pte_marker_entry()` at line
4521 and dispatches to `handle_pte_marker()` (line 4253):

```c
handle_pte_marker(vmf)
  → PTE_MARKER_POISONED?  → VM_FAULT_HWPOISON
  → PTE_MARKER_GUARD?     → VM_FAULT_SIGSEGV
  → PTE_MARKER_UFFD_WP?   → pte_marker_handle_uffd_wp(vmf)
```

`pte_marker_handle_uffd_wp()` (line 4241):
```c
if (unlikely(!userfaultfd_wp(vma)))
    return pte_marker_clear(vmf);    // stale marker, just remove it
return do_pte_missing(vmf);          // treat as a missing page
```

This dispatches back to `do_anonymous_page()` (or `do_fault()` for
file-backed), where `vmf_orig_pte_uffd_wp()` detects the marker and carries
the uffd-wp bit onto the newly installed PTE (see section 5).

### Marker propagation during fork

In `copy_nonpresent_pte()` (`mm/memory.c:890`), PTE markers are copied to the
child via `copy_pte_marker()` (`include/linux/mm_inline.h:542`):

```c
pte_marker dstm = srcm & (PTE_MARKER_POISONED | PTE_MARKER_GUARD);
if ((srcm & PTE_MARKER_UFFD_WP) && userfaultfd_wp(dst_vma))
    dstm |= PTE_MARKER_UFFD_WP;
```

The uffd-wp marker is only copied if the child's VMA also has `VM_UFFD_WP`.

---

## 8. Shmem MISSING Fault Path

### Entry

```
handle_pte_fault()
  → PTE is none
    → do_pte_missing()
      → vma_is_anonymous() is false (shmem)
        → do_fault()
          → vma->vm_ops->fault = shmem_fault()
```

### `shmem_fault()` → `shmem_get_folio_gfp()` (`mm/shmem.c:2497`)

The uffd MISSING check is at line 2573:

```c
// After page cache lookup and swap-in attempts have both failed to find a page:

if (vma && userfaultfd_missing(vma)) {
    *fault_type = handle_userfault(vmf, VM_UFFD_MISSING);
    return 0;
}
```

The check happens **after**:
1. `filemap_get_entry()` — checks the page cache (returns NULL)
2. Swap entry handling via `shmem_swapin_folio()` — no swap entry found
3. SGP checks — no page allocation needed yet

If MISSING is registered and no page exists, the fault is delivered to the
monitor, which resolves it via `UFFDIO_COPY` (for shmem, this goes through
`shmem_mfill_atomic_pte()` which adds the page to **both** the page cache and
the page table) or `UFFDIO_ZEROPAGE`.

---

## 9. Shmem MINOR Fault Path

### `shmem_get_folio_gfp()` — MINOR check (`mm/shmem.c:2521`)

```c
folio = filemap_get_entry(inode->i_mapping, index);
if (folio && vma && userfaultfd_minor(vma)) {
    if (!xa_is_value(folio))
        folio_put(folio);
    *fault_type = handle_userfault(vmf, VM_UFFD_MINOR);
    return 0;
}
```

**MINOR fault logic:** When a page **already exists** in the page cache
(`folio` is non-NULL) AND the VMA has `VM_UFFD_MINOR`, the fault is delivered
to userspace as a MINOR fault. This allows the monitor to modify page contents
(e.g., post-copy live migration — update page data received from the source)
before the page is mapped.

The page is **not** installed into the page table — that happens later via
`UFFDIO_CONTINUE`.

**Note:** If the entry is a swap value (`xa_is_value(folio)`), the MINOR check
is bypassed and the page is swapped in normally. MINOR only fires when a real
page cache page exists.

**Requires** `UFFD_FEATURE_MINOR_SHMEM` to be enabled via `UFFDIO_API`.

---

## 10. `handle_userfault()`: The Blocking Mechanism

`fs/userfaultfd.c:363` — called from all fault paths above.

**Parameters:** `vmf` (the vm_fault struct), `reason` (exactly one of
`VM_UFFD_MISSING`, `VM_UFFD_WP`, `VM_UFFD_MINOR`).

### Early exits (returns `VM_FAULT_SIGBUS`)

- Process is exiting (`PF_EXITING | PF_DUMPCORE`)
- `vma->vm_userfaultfd_ctx.ctx` is NULL
- `UFFD_FEATURE_SIGBUS` enabled (deliver SIGBUS instead of blocking)
- Non-user-mode fault with `UFFD_USER_MODE_ONLY`
- `FAULT_FLAG_ALLOW_RETRY` not set

### Blocking flow

1. **Build the fault message** (line 458):
   ```c
   uwq.msg = userfault_msg(vmf->address, vmf->real_address,
                            vmf->flags, reason, ctx->features);
   ```
   Sets `event = UFFD_EVENT_PAGEFAULT`, address (page-aligned or exact if
   `UFFD_FEATURE_EXACT_ADDRESS`), flags (`WRITE`, `WP`, `MINOR`), and
   optionally `ptid` for thread ID.

2. **Add to pending queue** (line 479):
   ```c
   spin_lock_irq(&ctx->fault_pending_wqh.lock);
   __add_wait_queue(&ctx->fault_pending_wqh, &uwq.wq);
   set_current_state(blocking_state);
   spin_unlock_irq(&ctx->fault_pending_wqh.lock);
   ```

3. **Must-wait check** (line 493): Before sleeping, `userfaultfd_must_wait()`
   walks the page tables **locklessly** to verify the fault condition still
   exists. For MISSING: checks `pte_none_mostly()`. For WP: checks
   `!pte_write()`. This avoids sleeping if another thread already resolved
   the fault.

4. **Release lock and sleep** (line 499):
   ```c
   release_fault_lock(vmf);                     // releases mmap_lock
   if (likely(must_wait && !READ_ONCE(ctx->released))) {
       wake_up_poll(&ctx->fd_wqh, EPOLLIN);     // notify monitor
       schedule();                                // BLOCK HERE
   }
   ```

5. **Return** `VM_FAULT_RETRY` — the page fault handler will retry from the
   top. By then, the monitor should have resolved the fault.

### The read path (`userfaultfd_ctx_read()`, line 973)

Called from `read()` on the uffd fd:
1. Takes `fd_wqh.lock`, adds itself to `fd_wqh`.
2. Calls `find_userfault()` — returns the last entry from
   `fault_pending_wqh` (FIFO).
3. **Refiles** the entry: `list_del` from `fault_pending_wqh`, `add_wait_queue`
   to `fault_wqh`. Protected by `refile_seq` seqcount.
4. Copies the `uffd_msg` and returns it.

### The wake path (`wake_userfault()`, line 1182)

Called after resolution ioctls (COPY, ZEROPAGE, CONTINUE, WRITEPROTECT):
- Uses seqcount to check both `fault_pending_wqh` and `fault_wqh`.
- `__wake_userfault()` wakes entries matching the resolved address range via
  the custom `userfaultfd_wake_function()` which checks address overlap and
  auto-removes the waker from the queue.

---

## 11. Resolution Ioctls

All resolution ioctls follow the same pattern:
1. Check `atomic_read(&ctx->mmap_changing)` — return `-EAGAIN` if non-zero
2. Copy ioctl struct from userspace, validate
3. Call the underlying `mfill_atomic_*` function
4. Write result back (bytes processed)
5. Unless `DONTWAKE` mode was set, call `wake_userfault()`

### UFFDIO_COPY (`fs/userfaultfd.c:1585`)

Resolves MISSING faults by copying user data to the faulting address.

Flow: `mfill_atomic_copy()` → `mfill_atomic()` → page-by-page loop →
`mfill_atomic_pte()` → dispatches to:
- **Anonymous:** `mfill_atomic_pte_copy()` (`mm/userfaultfd.c:237`)
  - Allocates a folio, copies data from userspace with page faults disabled
  - Calls `mfill_atomic_install_pte()` to install the PTE
- **Shmem:** `shmem_mfill_atomic_pte()` (`mm/shmem.c:3214`)
  - Allocates a shmem folio, copies data
  - Adds to **both** page cache (`shmem_add_to_page_cache()`) and page table

Supports `UFFDIO_COPY_MODE_WP` — installs the page with uffd-wp set.

### UFFDIO_ZEROPAGE (`fs/userfaultfd.c:1645`)

Maps zero pages at the faulting address.

For anonymous VMAs: installs the special zero-page PTE directly (no allocation)
unless `mm_forbids_zeropage()`, in which case a real zeroed folio is allocated.

**Important:** The zero-page path uses strict `pte_none()` (not
`pte_none_mostly()`), so it will **not** overwrite PTE markers.

### UFFDIO_WRITEPROTECT (`fs/userfaultfd.c:1699`)

Sets or clears write protection on a range.

Flow: → `mwriteprotect_range()` (`mm/userfaultfd.c:929`) → iterates VMAs →
`uffd_wp_range()` → `change_protection()` with `MM_CP_UFFD_WP` or
`MM_CP_UFFD_WP_RESOLVE`.

When **enabling** WP: Sets the uffd-wp bit on present PTEs, swap entries, and
installs PTE markers on none PTEs (if `userfaultfd_wp_use_markers()`).

When **resolving** (disabling) WP: Clears uffd-wp from present PTEs, removes
PTE markers entirely (`pte_clear()`), clears from swap entries.

Constraint: `WP + DONTWAKE` together is invalid (`-EINVAL`).

### UFFDIO_CONTINUE (`fs/userfaultfd.c:1751`)

Resolves MINOR faults by mapping an already-existing page cache page.

Flow: → `mfill_atomic_continue()` → `mfill_atomic_pte_continue()`
(`mm/userfaultfd.c:380`):

```c
shmem_get_folio(inode, pgoff, 0, &folio, SGP_NOALLOC);  // page MUST exist
page = folio_file_page(folio, pgoff);
mfill_atomic_install_pte(dst_pmd, dst_vma, dst_addr, page, false, flags);
```

Supports `UFFDIO_CONTINUE_MODE_WP` — maps with uffd-wp set.

### `mfill_atomic_install_pte()` — The shared PTE installer (`mm/userfaultfd.c:168`)

Used by COPY, ZEROPAGE (non-zero-pfn), and CONTINUE:

```c
_dst_pte = mk_pte(page, dst_vma->vm_page_prot);
_dst_pte = pte_mkdirty(_dst_pte);
if (writable)
    _dst_pte = pte_mkwrite(_dst_pte, dst_vma);
if (flags & MFILL_ATOMIC_WP)
    _dst_pte = pte_mkuffd_wp(_dst_pte);           // apply uffd-wp if requested

// Under page table lock:
if (!pte_none_mostly(ptep_get(dst_pte)))           // allows overwriting PTE markers
    goto out_unlock;                                // but not real PTEs
```

The `pte_none_mostly()` check at line 207 is critical: it allows resolution to
overwrite a `PTE_MARKER_UFFD_WP` marker with an actual page mapping. This
handles the case where both MISSING and WP are registered — the page is
wr-protected (installing a marker on the none PTE), then a fault triggers
MISSING, and `UFFDIO_COPY` overwrites the marker with a real page.

---

## 12. Unregistration and Cleanup

### `UFFDIO_UNREGISTER` (`fs/userfaultfd.c:1416`)

1. Validates that each VMA's ctx matches this uffd (prevents cross-uffd unregister)
2. For each VMA with `userfaultfd_missing()`, wakes all pending faults (so
   blocked threads don't hang forever)
3. Calls `userfaultfd_clear_vma()` (`mm/userfaultfd.c:1935`):
   - If WP was active: `uffd_wp_range(vma, ..., false)` to clear all WP bits
   - `vma_modify_flags_uffd()` — clears `__VM_UFFD_FLAGS`, sets `NULL_VM_UFFD_CTX`

### fd close (`userfaultfd_release()`, `fs/userfaultfd.c:859`)

1. Sets `ctx->released = true`
2. `userfaultfd_release_all()` — iterates all VMAs, calls
   `userfaultfd_clear_vma()` for each
3. Wakes all entries in `fault_pending_wqh`, `fault_wqh` (wake all), and
   `event_wqh`
4. Wakes `fd_wqh` with `EPOLLHUP`
5. Drops ctx reference → when last reference drops, `mmdrop(ctx->mm)` and free

---

## 13. Fork Handling

### `dup_userfaultfd()` (`fs/userfaultfd.c:616`)

Called per-VMA during `dup_mmap()` in fork:

- If `UFFD_FEATURE_EVENT_FORK` is **not** enabled: `userfaultfd_reset_ctx(vma)`
  clears the uffd context from the child's VMA. The child inherits no uffd
  handling.
- If `UFFD_FEATURE_EVENT_FORK` **is** enabled: creates a new `userfaultfd_ctx`
  for the child, points the child's VMA at it, increments `mmap_changing` on
  the parent's ctx (which makes resolution ioctls return `-EAGAIN`).

### `dup_userfaultfd_complete()` (`fs/userfaultfd.c:700`)

Called after fork completes: sends `UFFD_EVENT_FORK` to the parent's monitor
with a new file descriptor for the child's uffd context. The monitor can then
manage both parent and child.

### PTE-level fork behavior

In `copy_present_pte()` (`mm/memory.c:945`):
```c
if (userfaultfd_pte_wp(dst_vma, ptep_get(src_pte)))
    pte = pte_mkuffd_wp(pte);     // propagate uffd-wp to child
```

In `copy_nonpresent_pte()` (`mm/memory.c:890`): PTE markers are propagated
via `copy_pte_marker()` (only if child VMA has `VM_UFFD_WP`).

In `do_swap_page()` (`mm/memory.c:4796`): swap-in restores uffd-wp from swap
entries:
```c
if (pte_swp_uffd_wp(vmf->orig_pte))
    pte = pte_mkuffd_wp(pte);
```

---

## 14. Complete Fault Flow Diagrams

### Anonymous MISSING

```
Page fault (address with no PTE in anonymous VMA)
  │
  ├─ handle_pte_fault()           mm/memory.c:6019
  │    └─ vmf->pte == NULL
  │         └─ do_pte_missing()   mm/memory.c:4229
  │              └─ vma_is_anonymous() → true
  │                   └─ do_anonymous_page()  mm/memory.c:5005
  │                        ├─ [read fault] prepares zero-page PTE
  │                        │   └─ userfaultfd_missing(vma)?
  │                        │       ├─ YES → handle_userfault(VM_UFFD_MISSING)
  │                        │       │         └─ blocks, notifies monitor
  │                        │       └─ NO  → install zero-page PTE
  │                        └─ [write fault] allocates real folio
  │                            └─ userfaultfd_missing(vma)?
  │                                ├─ YES → folio_put(), handle_userfault(VM_UFFD_MISSING)
  │                                └─ NO  → install PTE (preserving uffd-wp if marker existed)
  │
  ├─ Monitor reads fault via read() on uffd fd
  │    └─ userfaultfd_ctx_read() refiles waiter to fault_wqh
  │
  ├─ Monitor resolves via UFFDIO_COPY
  │    └─ mfill_atomic_pte_copy()
  │         └─ alloc folio, copy_from_user(), mfill_atomic_install_pte()
  │              └─ set PTE (with MFILL_ATOMIC_WP if requested)
  │
  └─ wake_userfault() → faulting thread retries → PTE now present → success
```

### Anonymous WP (synchronous)

```
Page fault (write to uffd-wp-protected PTE)
  │
  ├─ handle_pte_fault()                mm/memory.c:6019
  │    └─ pte_present && WRITE && !pte_write
  │         └─ do_wp_page()            mm/memory.c:3921
  │              └─ userfaultfd_pte_wp(vma, pte)?
  │                  ├─ YES, !wp_async → handle_userfault(VM_UFFD_WP)
  │                  │                    └─ blocks, notifies monitor
  │                  └─ YES, wp_async  → pte_clear_uffd_wp(), fall through to COW
  │
  ├─ Monitor resolves via UFFDIO_WRITEPROTECT (un-protect)
  │    └─ mwriteprotect_range() → uffd_wp_range(enable_wp=false)
  │         └─ change_protection(MM_CP_UFFD_WP_RESOLVE)
  │              └─ change_pte_range(): pte_clear_uffd_wp()
  │
  └─ wake_userfault() → faulting thread retries → PTE now writable → success
```

### PTE Marker uffd-wp (none page that was write-protected)

```
Page fault (access to PTE marker)
  │
  ├─ handle_pte_fault()                mm/memory.c:6019
  │    └─ !pte_present (looks like swap entry)
  │         └─ do_swap_page()          mm/memory.c:4366
  │              └─ is_pte_marker_entry()?
  │                   └─ handle_pte_marker()    mm/memory.c:4253
  │                        └─ PTE_MARKER_UFFD_WP
  │                             └─ pte_marker_handle_uffd_wp()  mm/memory.c:4241
  │                                  └─ do_pte_missing()
  │                                       └─ do_anonymous_page()
  │                                            └─ install PTE with pte_mkuffd_wp()
  │                                               (uffd-wp bit carried from marker)
```

### Shmem MISSING

```
Page fault (address with no page in shmem page cache)
  │
  ├─ handle_pte_fault()
  │    └─ do_pte_missing() → do_fault() → shmem_fault()
  │         └─ shmem_get_folio_gfp()   mm/shmem.c:2497
  │              └─ filemap_get_entry() → NULL (no page in cache)
  │              └─ shmem_swapin_folio() → no swap entry
  │              └─ userfaultfd_missing(vma)?   line 2573
  │                  └─ YES → handle_userfault(VM_UFFD_MISSING)
  │
  ├─ Monitor resolves via UFFDIO_COPY
  │    └─ shmem_mfill_atomic_pte()     mm/shmem.c:3214
  │         └─ alloc shmem folio, copy_from_user()
  │         └─ shmem_add_to_page_cache()  (adds to page cache)
  │         └─ mfill_atomic_install_pte() (adds to page table)
  │
  └─ wake_userfault() → retry → page now in cache + page table → success
```

### Shmem MINOR

```
Page fault (page exists in shmem page cache but not mapped)
  │
  ├─ shmem_fault() → shmem_get_folio_gfp()
  │    └─ filemap_get_entry() → folio (page exists in cache!)
  │    └─ userfaultfd_minor(vma)?      line 2522
  │        └─ YES → handle_userfault(VM_UFFD_MINOR)
  │                  (page is NOT installed into page table yet)
  │
  ├─ Monitor may modify page contents (e.g., post-copy migration)
  │
  ├─ Monitor resolves via UFFDIO_CONTINUE
  │    └─ mfill_atomic_pte_continue()  mm/userfaultfd.c:380
  │         └─ shmem_get_folio(SGP_NOALLOC) → gets existing page
  │         └─ mfill_atomic_install_pte() → maps it into page table
  │
  └─ wake_userfault() → retry → PTE now present → success
```

---

## 15. Where bpf_fault Currently Hooks In

bpf_fault currently handles only anonymous MISSING faults. It hooks into
`do_anonymous_page()` immediately after the userfaultfd checks:

```c
// mm/memory.c, do_anonymous_page():

if (userfaultfd_missing(vma)) {         // line 5042 / 5095
    return handle_userfault(vmf, VM_UFFD_MISSING);
}
if (bpf_fault_set(vma)) {              // line 5046 / 5101
    return handle_bpf_fault(vmf);
}
```

`bpf_fault_set()` checks for `VM_BPF_FAULT` on the VMA (analogous to
`userfaultfd_missing()` checking `VM_UFFD_MISSING`).

bpf_fault also suppresses THP at the same points as userfaultfd (lines 4374,
4930, 5405) to maintain per-page fault granularity.

**Key difference from userfaultfd:** `handle_bpf_fault()` runs a BPF program
**synchronously in the fault path** and returns a page directly, rather than
blocking the faulting thread and notifying a separate monitor process.

---

## 16. Key Differences: bpf_fault vs userfaultfd

Understanding these differences is critical for extending bpf_fault to cover
WP, shmem MISSING, and shmem MINOR:

| Aspect | userfaultfd | bpf_fault |
|--------|-------------|-----------|
| **Execution model** | Async: block faulting thread, notify monitor process, monitor resolves via ioctl | Sync: BPF program runs in fault context, returns page directly |
| **Context** | `userfaultfd_ctx` (per-fd, shared across VMAs) | `bpf_fault_ctx` (per-link, stored in same VMA union) |
| **Page delivery** | Monitor copies data via `UFFDIO_COPY` / maps via `UFFDIO_CONTINUE` | BPF program provides page as `PTR_TO_MEM` argument |
| **VMA flags** | `VM_UFFD_MISSING`, `VM_UFFD_WP`, `VM_UFFD_MINOR` | `VM_BPF_FAULT` (currently only one flag) |
| **PTE installation** | `mfill_atomic_install_pte()` from ioctl context | Page table manipulation in `mm/bpf_fault.c` |
| **Blocking** | Faulting thread sleeps on wait queue | No blocking — BPF program must return immediately |
| **Locking** | Releases mmap_lock before sleeping | Holds fault lock throughout |

### Implications for extending bpf_fault

**For WP support:**
- Need to check a bpf_fault-specific PTE bit (or reuse the uffd-wp mechanism)
- BPF program would be called from `do_wp_page()` with write fault context
- Must handle the PTE marker infrastructure for none-page WP tracking
- Need equivalent of `change_protection()` for setting/clearing WP via BPF link

**For shmem MISSING:**
- Need to hook into `shmem_get_folio_gfp()` alongside the existing uffd check
- Resolution must add page to both page cache and page table
- Consider whether BPF program provides page data or a page cache reference

**For shmem MINOR:**
- Need to hook into `shmem_get_folio_gfp()` where MINOR is checked
- BPF program would receive the existing page-cache page for modification
- Resolution installs existing page into page table (like `UFFDIO_CONTINUE`)
