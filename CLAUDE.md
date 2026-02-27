# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a Linux 6.17 kernel tree with an in-development feature: **bpf_fault** — a BPF struct_ops-based page fault handler that allows BPF programs to intercept and handle anonymous page faults as an alternative to userfaultfd. The feature supports anonymous missing faults, shmem missing/minor faults, write-protect (WP) faults, SIGBUS delivery, multi-region registration (add/remove regions to a single link), fork inheritance (`BPF_FAULT_FLAG_INHERIT`), and post-fork claim (`BPF_FAULT_CLAIM`).

## Build Commands

### Using the helper script (preferred)
```bash
./build.py build                # Build with clang (default)
./build.py build --no-clang     # Build with GCC
./build.py build --debug        # Build with debug config options
./build.py install              # Build and install kernel + modules
```

The build script automatically enables required configs: `CONFIG_USERFAULTFD`, `CONFIG_PTE_MARKER_UFFD_WP`, `CONFIG_BPF`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_BPF_FAULT`, `CONFIG_TRACING`.

### Manual kernel build
```bash
make LLVM=1 CC=clang -j$(nproc)           # Build
make LLVM=1 CC=clang modules_install      # Install modules (sudo)
make LLVM=1 CC=clang install              # Install kernel (sudo)
```

### BPF selftests
```bash
make -C tools/testing/selftests/bpf       # Build BPF selftests
```

### bench_fault tests
```bash
make -C tools/testing/selftests/bpf/bench_fault   # Build all bench_fault programs
```

Targets: `bench_fault`, `bench_fault_scale`, `bench_fault_shmem`, `bench_fault_wp`, `test_shmem_fault`, `test_wp_fault`, `test_sigbus_fault`, `test_multi_region`, `test_fork_fault`

### bpftool
```bash
make -C tools/bpf/bpftool                 # Build bpftool
```

## bpf_fault Architecture

### Kernel-side components
- **`mm/bpf_fault.c`** — Core fault handling: page table manipulation, VMA setup/teardown, fault context lifecycle (refcounted `bpf_fault_ctx`), `bpf_fault_handle_pte()` entry point, WP fault support, multi-region register/unregister, fork inheritance (`bpf_fault_ctx_alloc_for_mm`, `bpf_fault_exit_mm`)
- **`kernel/bpf/bpf_fault_ops.c`** — BPF link type and struct_ops integration: `bpf_fault_ops_link` lifecycle, link create/update/detach, registration with the fault context, multi-region command dispatch, inherited link allocation, post-fork claim (`bpf_fault_ops_link_claim`)
- **`fs/userfaultfd.c`** — Fork path integration: `dup_userfaultfd()` handles bpf_fault inheritance via deduplication list (same pattern as userfaultfd fork contexts)
- **`mm/memory.c`** — Primary integration point: calls into bpf_fault from the anonymous page fault handler
- **`mm/shmem.c`** — shmem integration: intercepts missing/minor faults for shmem-backed VMAs
- **`mm/huge_memory.c`** — THP integration: falls back from huge page collapse when bpf_fault is active
- **`mm/khugepaged.c`** — khugepaged integration: skips collapse for bpf_fault VMAs
- **`include/linux/userfaultfd_k.h`** — `struct bpf_fault_ctx` definition (embedded in `vm_userfaultfd_ctx`), helper macros (`bpf_fault_missing()`, `bpf_fault_set()`)

### Config
- `CONFIG_BPF_FAULT` — defined in `mm/Kconfig`, depends on `USERFAULTFD && BPF_JIT && 64BIT`

### Userspace tooling (modified)
- **`tools/lib/bpf/libbpf.c`** and **`tools/lib/bpf/bpf.h`** — libbpf support for bpf_fault struct_ops
- **`tools/bpf/bpftool/link.c`** — bpftool link display support for fault_ops links

### BPF programs (bench_fault)
- **`fault_ops.bpf.c`** — BPF handler for anonymous missing faults
- **`wp_fault_ops.bpf.c`** — BPF handler for write-protect faults
- **`sigbus_fault_ops.bpf.c`** — BPF handler that rejects missing faults (triggers SIGBUS)

## Kernel Coding Conventions

- Follow `Documentation/process/coding-style.rst` (tabs, 80-col soft limit, K&R braces)
- SPDX license identifiers required: `// SPDX-License-Identifier: GPL-2.0-only`
- AI agents must NOT add `Signed-off-by` tags — only humans certify the DCO
- AI-assisted contributions should include: `Assisted-by: Claude:claude-opus-4-6`
- Do NOT add `Co-Authored-By` tags to kernel commits
- See `Documentation/process/coding-assistants.rst` for full AI contribution guidelines
