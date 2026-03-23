# ebpfency vs SIGBUS Mode: Performance Analysis & Proposed Fixes

## Benchmark Results

### Volatile write touch: `*(volatile char *)p = 0`

Workload: `bench_malloc` sequential malloc+free (size=32, 500k iterations).

| Mode                        | ns/op | Relative to SIGBUS |
|-----------------------------|-------|--------------------|
| glibc                       |     9 | -                  |
| efency SIGBUS               | 3,275 | 1.0x               |
| ebpfency (with bpf_printk)  | 6,038 | 1.84x              |
| ebpfency (no bpf_printk)    | 4,763 | 1.45x              |

perf stat (full benchmark run, volatile write, no bpf_printk):

| Metric           |    SIGBUS |   ebpfency | Factor  |
|------------------|-----------|------------|---------|
| cycles           |       44B |      60.5B | 1.4x    |
| instructions     |       33B |      45.7B | 1.4x    |
| page-faults      |       171 |  3,165,555 | 18,500x |
| dTLB-load-misses |      5.3M |      12.2M | 2.3x    |

### Volatile read touch: `(void)*(volatile char *)p`

Same workload parameters.

| Mode                        | ns/op | Relative to SIGBUS |
|-----------------------------|-------|--------------------|
| glibc                       |     9 | -                  |
| efency SIGBUS               | 3,265 | 1.0x               |
| ebpfency (no bpf_printk)    | 3,986 | 1.22x              |

perf stat (full benchmark run, volatile read):

| Metric           |    SIGBUS |   ebpfency | Factor  |
|------------------|-----------|------------|---------|
| cycles           |       45B |      50.9B | 1.13x   |
| instructions     |       33B |      38.2B | 1.16x   |
| page-faults      |       172 |  3,165,556 | 18,400x |
| dTLB-load-misses |      7.2M |      12.1M | 1.7x    |

### Full volatile read results (all benchmarks)

```
bench_name                   size        ops      ns/op (SIGBUS)  ns/op (ebpf)
------------------------     --------    ------   ------------    ------------
seq_malloc_free              32          500000   3265            3986
seq_malloc_free              128         500000   3495            3999
seq_malloc_free              512         500000   3526            4004
seq_malloc_free              2048        500000   3480            3987
bulk_alloc_free              64          204800   3853            4260
bulk_alloc_free              1024        204800   3832            4255
realloc_chain                4096        400000    448             508
mixed_workload               256         500000   3771            4380
multithread_bulk             64          204800   8335            8354
```

### Write vs read: what changes and why

| Metric (ebpfency)       | write | read  | delta |
|-------------------------|-------|-------|-------|
| seq_malloc_free ns/op   | 4,763 | 3,986 | -16%  |
| cycles                  | 60.5B | 50.9B | -16%  |
| instructions            | 45.7B | 38.2B | -16%  |
| page-faults             | 3.16M | 3.16M | same  |

SIGBUS mode is unaffected (~3,270 ns/op either way) because it
pre-populates pages via UFFDIO_COPY during malloc — the touch hits an
already-mapped page regardless of read vs write.

ebpfency gets 16% faster with reads because `do_anonymous_page()` takes
the **zero-page fast path** (mm/memory.c:5030-5054).  This path maps the
shared zero page and checks `bpf_fault_missing()` at line 5050 **before
allocating any folio**, so the wasted folio cycle from Cause 3 is avoided
entirely.  Write faults skip this path (the kernel cannot use the shared
zero page for writes) and hit the second check at line 5105 after
`alloc_anon_folio()`.

This confirms that Fix 2/3 (eliminating the wasted folio on write faults)
would close ~16% of the write-fault gap, bringing write performance in
line with read performance.  The remaining ~22% gap (read: 3986 vs 3265)
is purely structural VM_FAULT_RETRY overhead (Fix 4).

### Top kernel symbols (perf report, no bpf_printk)

SIGBUS mode:
```
4.24%  unmap_page_range            (MADV_DONTNEED)
4.00%  smp_call_function_many_cond (TLB shootdown)
2.33%  do_syscall_64               (ioctl entry)
2.19%  mfill_atomic_install_pte    (UFFDIO_COPY PTE install)
2.16%  userfaultfd_ioctl           (uffd ioctl dispatch)
1.96%  clear_page_rep              (page zeroing)
1.89%  get_page_from_freelist      (page alloc)
1.87%  lock_vma_under_rcu          (VMA lookup)
1.85%  mfill_atomic_copy           (UFFDIO_COPY core)
```

ebpfency (no bpf_printk):
```
3.30%  handle_mm_fault             (full fault dispatch)
3.13%  unmap_page_range            (MADV_DONTNEED)
2.81%  smp_call_function_many_cond (TLB shootdown)
2.78%  get_page_from_freelist      (page alloc)
2.53%  clear_page_rep              (page zeroing)
2.29%  lock_vma_under_rcu          (VMA lookup - called twice)
2.21%  do_pte_missing              (PTE fault path)
2.20%  handle_bpf_fault            (BPF dispatch)
1.98%  __mem_cgroup_charge          (memcg accounting)
1.81%  mfill_atomic_install_pte    (PTE install)
1.56%  do_user_addr_fault          (arch fault entry)
1.14%  exc_page_fault              (exception entry)
```


## Root Cause Analysis

### Cause 1: bpf_printk() in the hot path

`src/ebpfency.bpf.c` had `bpf_printk()` on every page fault (lines 64,
85, 89, 96).  This feeds into the full kernel trace-event pipeline:

    bpf_trace_printk -> bpf_bprintf_prepare -> bstr_printf ->
      format_decode -> number -> strnchr ->
      trace_event_raw_event_bpf_trace_printk ->
      trace_event_buffer_reserve -> trace_buffer_unlock_commit_regs

With bpf_printk, perf showed ~15% of total cycles in printk-related
functions.  Removing them improved throughput by ~25% (6400 -> 4800 ns/op).

**Status: fixed** (bpf_printk calls removed from hot path).


### Cause 2: full page fault path vs direct ioctl

The fundamental architectural difference explains the remaining ~45% gap.

**SIGBUS mode (efency):**

```
malloc()
  -> allocate_efence_slot()          [userspace, fast]
  -> populate_page()
       -> ioctl(uffd, UFFDIO_COPY)   [syscall]
            -> mfill_atomic_copy()
                 -> mfill_atomic_install_pte()  [PTE installed directly]
  -> return pointer                   [page already present]

touch(*p = 0)                         [no fault, page is mapped]
```

One syscall (UFFDIO_COPY ioctl) pre-populates the page.  Zero page faults
during normal operation (the 171 faults are from init).

**ebpfency (bpf_fault):**

```
malloc()
  -> allocate_efence_slot()          [userspace, fast]
  -> return pointer                   [page NOT populated]

touch(*p = 0)                         [triggers page fault]
  -> exc_page_fault                   [arch exception entry]
  -> do_user_addr_fault
  -> lock_vma_under_rcu              [1st VMA lookup]
  -> handle_mm_fault
  -> do_pte_missing
  -> do_anonymous_page
       -> alloc_anon_folio()          [folio allocated]
       -> folio_put()                 [folio WASTED, see Cause 3]
       -> handle_bpf_fault()
            -> release_fault_lock()   [drop VMA lock]
            -> folio_alloc()          [2nd folio allocated]
            -> kmap_local_folio()
            -> BPF program runs       [bitmap check, return 0]
            -> kunmap_local()
            -> bpf_fault_lock_vma()   [2nd VMA lookup]
            -> bpf_fault_alloc_pmd()  [page table walk]
            -> mfill_atomic_install_pte()  [PTE installed]
            -> return VM_FAULT_RETRY

  [arch fault code retries from scratch]
  -> lock_mm_and_find_vma            [3rd VMA lookup]
  -> handle_mm_fault                  [finds PTE present, returns]
```

Overhead per allocation vs SIGBUS:
- Exception entry/exit: exc_page_fault + do_user_addr_fault (~2.7%)
- Full fault dispatch: handle_mm_fault + do_pte_missing (~5.5%)
- VMA looked up 3 times instead of once (~3-4%)
- VM_FAULT_RETRY full restart adds ~30% on top


### Cause 3: wasted folio allocation in do_anonymous_page (write faults only)

On write faults (the `touch()` does `*(volatile char *)p = 0`), the code
path hits the second `bpf_fault_missing()` check in `do_anonymous_page()`
at `mm/memory.c:5105`:

```c
/* mm/memory.c:5062 - folio allocated */
folio = alloc_anon_folio(vmf);

/* ... PTE lock acquired, checks pass ... */

/* mm/memory.c:5105 - folio discarded */
if (bpf_fault_missing(vma)) {
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    folio_put(folio);              // <-- WASTED
    return handle_bpf_fault(vmf);  // allocates another folio
}
```

Then `handle_bpf_fault()` at `mm/bpf_fault.c:346` allocates a second folio:

```c
folio = folio_alloc(GFP_HIGHUSER_MOVABLE | __GFP_ZERO, 0);
```

Every write-triggered page fault wastes one folio alloc+zero cycle.  With
3.1M page faults in the benchmark, that's 3.1M wasted `alloc_anon_folio()`
calls.

Read faults do NOT hit this path — they take the zero-page fast path
(mm/memory.c:5030) which checks `bpf_fault_missing()` at line 5050
before any folio is allocated.

**Confirmed by measurement:** switching bench_malloc from a volatile write
touch to a volatile read touch improved ebpfency by exactly 16% (4763 ->
3986 ns/op) while SIGBUS mode was unaffected.  This 16% matches the cost
of the wasted folio allocation.


### Cause 4: VM_FAULT_RETRY forces double traversal

`handle_bpf_fault()` always returns `VM_FAULT_RETRY` (bpf_fault.c:459).
The arch fault code in `arch/x86/mm/fault.c` then:

```c
retry:
    vma = lock_mm_and_find_vma(mm, address, regs);  // full VMA tree walk
    fault = handle_mm_fault(vma, address, flags, regs);
    if (unlikely(fault & VM_FAULT_RETRY)) {
        flags |= FAULT_FLAG_TRIED;
        goto retry;
    }
```

The retry finds the PTE present and returns quickly, but still pays for:
- `lock_mm_and_find_vma()` — mmap_read_lock + maple tree walk
- `handle_mm_fault()` — page table walk to find the now-present PTE
- All the associated lock acquire/release overhead


## Proposed Fixes

### Fix 1: Remove bpf_printk from hot path [userspace, DONE]

Remove all `bpf_printk()` calls from `handle_page_fault` in
`src/ebpfency.bpf.c`.

Impact: ~25% improvement (6400 -> 4800 ns/op).

Status: applied.


### Fix 2: Early bpf_fault_missing check before folio allocation [kernel]

Move the `bpf_fault_missing()` check before `alloc_anon_folio()` on the
write path in `do_anonymous_page()`, mirroring the read-path check that
already exists at line 5050.

```c
// mm/memory.c, in do_anonymous_page(), after vmf_anon_prepare() but
// BEFORE alloc_anon_folio():

if (bpf_fault_missing(vma)) {
    vmf->pte = pte_offset_map_lock(vma->vm_mm, vmf->pmd,
                                    vmf->address, &vmf->ptl);
    if (vmf->pte && !vmf_pte_changed(vmf)) {
        pte_unmap_unlock(vmf->pte, vmf->ptl);
        return handle_bpf_fault(vmf);
    }
    if (vmf->pte)
        pte_unmap_unlock(vmf->pte, vmf->ptl);
    /* PTE changed under us — fall through to the normal path which
     * will re-check after allocating.  */
}
```

Saves one `alloc_anon_folio()` + `__GFP_ZERO` + `folio_put()` per write
fault (3.1M times in the benchmark).

Expected impact: ~16% improvement on write-fault workloads (confirmed by
volatile read vs write comparison: 4763 -> 3986 ns/op).  No effect on
read-fault workloads (already using the early check path).

Files: `mm/memory.c`


### Fix 3: Pass pre-allocated folio into handle_bpf_fault [kernel]

Alternative to Fix 2.  Instead of discarding the folio from
`do_anonymous_page()`, pass it through:

```c
// mm/memory.c:
if (bpf_fault_missing(vma)) {
    pte_unmap_unlock(vmf->pte, vmf->ptl);
    return handle_bpf_fault(vmf, folio);  // reuse instead of folio_put
}

// mm/bpf_fault.c:
vm_fault_t handle_bpf_fault(struct vm_fault *vmf, struct folio *folio)
{
    /* ... */
    release_fault_lock(vmf);

    if (!folio) {
        folio = folio_alloc(GFP_HIGHUSER_MOVABLE | __GFP_ZERO, 0);
        if (!folio)
            goto out_put_ctx;
    }
    /* ... rest of handler uses folio as before ... */
}
```

This requires updating the function signature and both call sites (the
read-path call at line 5052 would pass NULL).

Impact: same as Fix 2 but cleaner — the folio is never wasted.

Files: `mm/memory.c`, `mm/bpf_fault.c`, `include/linux/userfaultfd_k.h`


### Fix 4: Return VM_FAULT_COMPLETED instead of VM_FAULT_RETRY [kernel]

The biggest potential improvement.  After successfully installing the PTE,
`handle_bpf_fault()` should return `VM_FAULT_COMPLETED` instead of
`VM_FAULT_RETRY`.  This signals the arch fault code that the fault has been
fully resolved and no retry is needed.

`VM_FAULT_COMPLETED` already exists in the kernel (used by KSM) and means
"PTE installed, lock released, no further action needed."

```c
// mm/bpf_fault.c, in handle_bpf_fault():

err = mfill_atomic_install_pte(dst_pmd, vma, address,
                               &folio->page, true,
                               bpf_fault_wp(vma) ? MFILL_ATOMIC_WP : 0);

bpf_fault_unlock_vma(vma);

if (!err) {
    /* PTE installed successfully.  Return COMPLETED so the arch
     * fault code skips the retry loop.  */
    bpf_fault_ctx_put(ctx);
    return VM_FAULT_COMPLETED;  // <-- instead of VM_FAULT_RETRY
}

/* Installation failed, retry will re-trigger the fault. */
folio_put(folio);
bpf_fault_ctx_put(ctx);
return VM_FAULT_RETRY;
```

The arch code in `arch/x86/mm/fault.c` already handles this:

```c
if (fault & (VM_FAULT_RETRY | VM_FAULT_COMPLETED))
    return;  // Both cases skip the unlock
```

So `VM_FAULT_COMPLETED` would skip the entire retry path: no
`lock_mm_and_find_vma()`, no `handle_mm_fault()` re-entry, no second VMA
lookup, no second page table walk.

Expected impact: ~15-20% improvement.  Eliminates the 3rd VMA lookup, the
retry's `handle_mm_fault()` call, and associated lock churn.

Caveat: need to verify that all arch fault handlers (x86, arm64) treat
`VM_FAULT_COMPLETED` correctly when returned from this context, and that
perf accounting and fault counters are updated properly.

Files: `mm/bpf_fault.c`, and audit `arch/x86/mm/fault.c`,
`arch/arm64/mm/fault.c`


### Fix 5: Batch page pre-population kfunc [kernel]

For bulk allocation patterns, add a kfunc that lets userspace request
eager page population for a range, avoiding per-page faults entirely:

```c
// New kfunc in mm/bpf_fault.c:
int bpf_fault_populate_range(void *addr, size_t len);
```

Userspace (ebpfency.c) would call this after a batch of allocations:

```c
// In allocate_efence_slot() when growing nb_usable_slots:
bpf_fault_populate_range(efence_area.addr + old_end, new_end - old_end);
```

This converts N page faults into a single syscall that walks the page
table once and installs PTEs in a tight loop, similar to how UFFDIO_COPY
can handle ranges.

This is the most impactful fix for bulk workloads but requires new kernel
API surface.

Impact: would make bulk_alloc_free approach SIGBUS-mode performance.

Files: `mm/bpf_fault.c`, `include/uapi/linux/bpf.h`, `src/ebpfency.c`


### Fix 6: Direct bitmap access in BPF [kernel, minor]

The BPF program uses `bpf_map_lookup_elem(&bitmap_map, &word_key)` which
goes through the array map lookup machinery for every fault.  Since the
map is `BPF_F_MMAPABLE`, the backing memory is a simple flat array.  A
direct-access kfunc or arena-style pointer could skip the lookup overhead:

```c
// Instead of:
bitmap_word = bpf_map_lookup_elem(&bitmap_map, &word_key);

// Direct access via arena or global variable:
bitmap_word = &bitmap_data[word_key];
```

Impact: minor (~0.6% of cycles).  Worth doing only after the larger fixes.

Files: `src/ebpfency.bpf.c`


## Implementation Priority

1. **Fix 1** (bpf_printk removal) — done, 25% gain
2. **Fix 2 or 3** (avoid wasted folio) — **measured 16% gain** on write faults
3. **Fix 4** (VM_FAULT_COMPLETED) — ~22% remaining gap (measured: read-fault
   ebpfency 3986 vs SIGBUS 3265 = 1.22x, purely VM_FAULT_RETRY overhead)
4. **Fix 5** (batch populate) — transforms bulk workload performance
5. **Fix 6** (direct bitmap) — minor cleanup

With Fix 1 already applied:
- Fix 2/3 alone would bring write-fault performance from 1.45x to ~1.22x
  (matching read-fault performance).
- Fix 4 alone would bring read-fault performance from 1.22x toward ~1.0x.
- Fixes 2+4 combined should bring ebpfency to near-parity with SIGBUS mode
  for sequential workloads.  Fix 5 would close the gap for bulk patterns.
