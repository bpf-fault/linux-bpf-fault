# Technical Plan: Write-Protect Support for bpf_fault (Anonymous Pages)

## 1. Background & Goal

Userfaultfd write-protect (uffd-wp) allows userspace to write-protect individual PTEs within a VMA, triggering a fault notification on write. The goal is to replicate this for bpf_fault: BPF programs should be able to WP-protect/unprotect page ranges, handle write-protection faults in BPF, and userspace should be able to toggle WP from outside the BPF program too.

The existing uffd-wp mechanism works through:
1. **Registration**: `UFFDIO_REGISTER` with `UFFDIO_REGISTER_MODE_WP` sets `VM_UFFD_WP` on the VMA
2. **Protecting pages**: `UFFDIO_WRITEPROTECT` ioctl calls `mwriteprotect_range()` -> `uffd_wp_range()` -> `change_protection()` with `MM_CP_UFFD_WP` or `MM_CP_UFFD_WP_RESOLVE`
3. **Fault interception**: `do_wp_page()` checks `userfaultfd_pte_wp()` -- if the PTE has the uffd-wp bit set and the VMA has `VM_UFFD_WP`, it calls `handle_userfault(vmf, VM_UFFD_WP)`
4. **PTE markers**: For unpopulated pages, `PTE_MARKER_UFFD_WP` swap entries preserve the WP state across zap/unmap, so pages remain protected even after being paged out or unmapped

## 2. Design Decisions

### 2.1 VMA Flag: Reuse `VM_UFFD_WP` vs. New Flag

**Decision: Add a new `VM_BPF_FAULT_WP` flag.**

Reusing `VM_UFFD_WP` is tempting since the PTE-level machinery (`pte_mkuffd_wp`, `pte_uffd_wp`, `pte_clear_uffd_wp`, `PTE_MARKER_UFFD_WP`) is already wired throughout `mm/memory.c`, `mm/mprotect.c`, `mm/rmap.c`, etc. However:

- `VM_UFFD_WP` is checked via `userfaultfd_wp(vma)` which is used broadly (e.g., `do_wp_page`, `vmf_orig_pte_uffd_wp`, `userfaultfd_wp_use_markers`, `uffd_disable_fault_around`, `uffd_disable_huge_pmd_share`, `copy_nonpresent_pte`, etc.) to gate uffd-specific behavior.
- `vm_userfaultfd_ctx` is a union -- `ctx` vs `bpf_ctx` -- so checking `userfaultfd_wp()` would succeed on bpf_fault VMAs, but any code that then dereferences `vma->vm_userfaultfd_ctx.ctx` (e.g., `userfaultfd_wp_unpopulated()`, `userfaultfd_wp_async()`) would type-confuse the pointer.
- `vma_has_uffd_without_event_remap()` already guards against this, showing the pattern is fragile.

### 2.2 PTE-Level WP Bits: Reuse Existing uffd-wp PTE Infrastructure

The PTE-level bits (`_PAGE_UFFD_WP` / software PTE bit) and swap entry bits (`pte_swp_uffd_wp`) are **not tied to userfaultfd semantics** -- they're generic "this PTE is write-protected by a fault handler" markers. We reuse them directly. The VMA-level flag determines which handler is invoked; the PTE-level bit is just the protection mechanism.

### 2.3 Fault-Path Dispatch

In `do_wp_page()`, after the existing userfaultfd check, add a bpf_fault WP check that dispatches to `handle_bpf_fault_wp()`.

### 2.4 WP-Async Equivalent

Not needed as a separate feature. The BPF program decides the policy:
- Return 0 from the WP fault handler -> resolve the protection
- Return non-zero -> SIGBUS

## 3. Implementation Steps

### Step 1: VMA Flag and Registration

**Files**: `include/linux/mm.h`, `include/linux/userfaultfd_k.h`, `mm/bpf_fault.c`, `include/uapi/linux/bpf.h`

1. Define `VM_BPF_FAULT_WP` (bit 44) in `include/linux/mm.h`
2. Add `bpf_fault_wp()`, `bpf_fault_pte_wp()` helpers in `include/linux/userfaultfd_k.h`
3. Update `bpf_fault_register()` to accept WP flag via `bpf_attr.link_create.fault.flags`
4. Define `__VM_BPF_FAULT_FLAGS` for clearing both `VM_BPF_FAULT | VM_BPF_FAULT_WP`
5. Update `bpf_fault_clear_vma()` to also clear `VM_BPF_FAULT_WP`

### Step 2: Fault Path Integration

**Files**: `mm/memory.c`, `mm/bpf_fault.c`

1. Add `bpf_fault_pte_wp()` check in `do_wp_page()` after userfaultfd check
2. Implement `handle_bpf_fault_wp()` -- calls BPF program, resolves WP on allow
3. Update `pte_marker_handle_uffd_wp()` to recognize `bpf_fault_wp()`
4. Update `vmf_orig_pte_uffd_wp()` to also check `bpf_fault_wp()`
5. Add TLB flush check for `bpf_fault_wp()` in `do_wp_page()`

### Step 3: struct_ops and BPF Verifier Updates

**Files**: `mm/bpf_fault.c`, `include/linux/mm_types.h`

1. Extend `fault_ops` with `handle_wp_fault` callback
2. Extend `bpf_fault_ops_ctx` with fault type info
3. Update verifier access checks for new context fields
4. Add default `__bpf_fault_handle_wp_fault` stub

### Step 4: Protect/Unprotect Interface -- BPF kfunc

**Files**: `mm/bpf_fault.c`

1. Implement `bpf_fault_writeprotect()` kfunc
2. Register kfunc with the fault_ops struct_ops program type
3. The kfunc calls `change_protection()` with `MM_CP_UFFD_WP` / `MM_CP_UFFD_WP_RESOLVE`

### Step 5: Protect/Unprotect Interface -- Userspace

**Files**: `kernel/bpf/bpf_fault_ops.c`, `include/uapi/linux/bpf.h`

1. Add ioctl on bpf_fault link fd for userspace WP control
2. Implement via `bpf_link_ops` -- new subcommand through bpf() syscall

### Step 6: PTE Marker and Unmap Handling

**Files**: `mm/memory.c`, `mm/mprotect.c`

1. Update `uffd_disable_fault_around()` for bpf_fault_wp
2. Update `uffd_disable_huge_pmd_share()` for bpf_fault_wp
3. Update `copy_present_ptes()` to preserve uffd-wp bit for bpf_fault_wp VMAs
4. Add `CONFIG_PTE_MARKER_UFFD_WP` dependency to `CONFIG_BPF_FAULT`

### Step 7: Teardown and Lifecycle

**Files**: `mm/bpf_fault.c`, `kernel/fork.c`

1. Update `bpf_fault_clear_vma()` to resolve WP before clearing flags
2. Handle fork: clear bpf_fault WP in child VMAs
3. Ensure `bpf_fault_release_all()` cleans up WP state

## 4. Key Technical Challenges

- **Lock ordering**: WP fault handler must release PTE lock before calling BPF, then retry
- **Re-entrant WP resolution**: kfunc resolving WP on faulting address must not re-trap
- **`mfill_atomic_install_pte()` integration**: Pass `MFILL_ATOMIC_WP` for WP-registered VMAs
- **Union ambiguity**: Never allow `VM_UFFD_WP` and `VM_BPF_FAULT_WP` on same VMA
- **TLB flush correctness**: Deferred flushes from WP range operations
- **Scope**: Anonymous pages only initially

## 5. Files Changed Summary

| File | Changes |
|------|---------|
| `include/linux/mm.h` | `VM_BPF_FAULT_WP` definition |
| `include/linux/mm_types.h` | Extend `bpf_fault_ops_ctx`, `fault_ops` |
| `include/linux/userfaultfd_k.h` | `bpf_fault_wp()`, `bpf_fault_pte_wp()` helpers; update stubs |
| `include/uapi/linux/bpf.h` | WP flag for link_create, WP ioctl structs |
| `mm/bpf_fault.c` | `handle_bpf_fault_wp()`, `bpf_fault_wp_range()`, kfunc, registration, teardown |
| `kernel/bpf/bpf_fault_ops.c` | Link ioctl for userspace WP |
| `mm/memory.c` | `do_wp_page()` dispatch, `vmf_orig_pte_uffd_wp()`, `pte_marker_handle_uffd_wp()`, TLB flush |
| `mm/Kconfig` | `CONFIG_BPF_FAULT` dependency on `CONFIG_PTE_MARKER_UFFD_WP` |
| `kernel/fork.c` | Fork handling for bpf_fault WP VMAs |
| `include/trace/events/mmflags.h` | `VM_BPF_FAULT_WP` trace flag |
