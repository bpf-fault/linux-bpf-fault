# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Overview

This is a Linux 6.17 kernel tree with an in-development feature: **bpf_fault** — a BPF struct_ops-based page fault handler that allows BPF programs to intercept and handle anonymous page faults as an alternative to userfaultfd.

## Build Commands

### Using the helper script (preferred)
```bash
./build.py build                # Build with clang (default)
./build.py build --no-clang     # Build with GCC
./build.py build --debug        # Build with debug config options
./build.py install              # Build and install kernel + modules
```

The build script automatically enables required configs: `CONFIG_USERFAULTFD`, `CONFIG_PTE_MARKER_UFFD_WP`, `CONFIG_BPF`, `CONFIG_DEBUG_INFO_BTF`, `CONFIG_BPF_FAULT`.

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

### bpftool
```bash
make -C tools/bpf/bpftool                 # Build bpftool
```

## bpf_fault Architecture

### Kernel-side components
- **`mm/bpf_fault.c`** — Core page fault handling logic: page table manipulation, VMA setup/teardown, fault context lifecycle (refcounted `bpf_fault_ctx`), and the `bpf_fault_handle_pte()` entry point called from the page fault path
- **`kernel/bpf/bpf_fault_ops.c`** — BPF link type and struct_ops integration: `bpf_fault_ops_link` lifecycle, link create/update/detach, registration with the fault context
- **`mm/memory.c`** — Integration point: calls into bpf_fault from the kernel's page fault handler
- **`include/linux/userfaultfd_k.h`** — `struct bpf_fault_ctx` definition (embedded in `vm_userfaultfd_ctx`)

### Config
- `CONFIG_BPF_FAULT` — defined in `mm/Kconfig`, depends on `USERFAULTFD && BPF_JIT && 64BIT`

### Userspace tooling (modified)
- **`tools/lib/bpf/libbpf.c`** and **`tools/lib/bpf/bpf.h`** — libbpf support for bpf_fault struct_ops
- **`tools/bpf/bpftool/link.c`** — bpftool link display support for fault_ops links

## Kernel Coding Conventions

- Follow `Documentation/process/coding-style.rst` (tabs, 80-col soft limit, K&R braces)
- SPDX license identifiers required: `// SPDX-License-Identifier: GPL-2.0-only`
- AI agents must NOT add `Signed-off-by` tags — only humans certify the DCO
- AI-assisted contributions should include: `Assisted-by: Claude:claude-opus-4-6`
- See `Documentation/process/coding-assistants.rst` for full AI contribution guidelines
