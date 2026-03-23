# bpf_fault(7) - BPF-based page fault handling

## NAME

bpf_fault - intercept and handle page faults via BPF struct_ops programs

## SYNOPSIS

```c
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/bpf.h>

struct bpf_link *bpf_map__attach_fault_ops(const struct bpf_map *map,
                                           void *start, unsigned long len,
                                           unsigned int flags);

int bpf_link__fault_register(int link_fd, __u64 start, __u64 len);
int bpf_link__fault_unregister(int link_fd, __u64 start, __u64 len);
int bpf_link__fault_claim(int parent_link_fd);

int syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, union bpf_attr *attr,
            sizeof(*attr));
```

## DESCRIPTION

bpf_fault is a BPF struct_ops-based mechanism for intercepting anonymous
page faults in userspace memory regions.  It provides an in-kernel
alternative to userfaultfd(2) with significantly lower latency, as fault
handling executes synchronously in the faulting thread's context rather
than requiring IPC to a handler thread.

bpf_fault supports two fault modes, selectable at registration time:

**Missing fault mode** (default)
:   Intercepts faults on pages that are not yet present in the page
    tables.  The BPF program receives a pointer to a kernel-allocated
    zeroed page and fills it with the desired content.  The kernel then
    installs the page into the faulting process's page tables.

**Write-protect (WP) mode** (`BPF_FAULT_FLAG_WP`)
:   Intercepts write faults on pages that have been explicitly
    write-protected via `BPF_LINK_FAULT_OPS_CMD`.  The BPF program
    decides whether to allow or deny each write.  This operates at
    PTE granularity using uffd-wp PTE markers, without VMA splitting.

These modes are currently mutually exclusive per registration.

A single link can manage multiple disjoint memory regions via
`BPF_FAULT_REGISTER` / `BPF_FAULT_UNREGISTER` commands, and
registrations can optionally be inherited across `fork()` with the
`BPF_FAULT_FLAG_INHERIT` flag.

## BPF PROGRAM INTERFACE

### struct_ops definition

```c
struct fault_ops {
    int (*handle_page_fault)(struct bpf_fault_ops_ctx *ctx,
                             unsigned char *page);
    int (*handle_wp_fault)(struct bpf_fault_ops_ctx *ctx,
                           unsigned char *page);
};
```

### Fault context

```c
struct bpf_fault_ops_ctx {
    unsigned long address;      /* faulting virtual address (page-aligned) */
    unsigned long real_address; /* faulting virtual address (exact) */
    __u32 fault_type;           /* BPF_FAULT_MISSING or BPF_FAULT_WP */
};
```

### Callbacks

**handle_page_fault**(ctx, page)
:   Called on a missing page fault.  `ctx->address` is the page-aligned
    faulting address; `ctx->real_address` is the exact faulting address.
    `page` points to a PAGE_SIZE buffer of kernel memory, pre-zeroed.
    For file-backed (shmem) VMAs, the buffer is pre-filled with the
    current file content at the faulting offset.

    The program should fill `page` with the desired content and return 0
    to install the page.  A non-zero return delivers SIGBUS to the
    faulting process.

    The program runs with the VMA lock released and under RCU read-side
    protection.  It must not sleep.

**handle_wp_fault**(ctx, page)
:   Called on a write-protect fault (write to a page with the uffd-wp
    PTE bit set).  `page` points to a PAGE_SIZE buffer containing the
    current contents of the faulting page (read-only view).  Return 0
    to allow the write (clears the wp bit on the faulting PTE).  A
    non-zero return delivers SIGBUS.

    The program runs with the VMA lock released and under RCU read-side
    protection.  It must not sleep.

### BPF program structure

Programs use the `SEC("struct_ops/...")` and `SEC(".struct_ops.link")`
ELF sections.  A complete example:

```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ctx,
             unsigned char *buf)
{
    volatile unsigned long *p = (volatile unsigned long *)buf;
    unsigned long fill = 0x4141414141414141UL;

    for (int i = 0; i < 4096 / (int)sizeof(unsigned long); i++)
        p[i] = fill;
    return 0;
}

SEC("struct_ops/handle_wp_fault")
int BPF_PROG(handle_wp_fault, struct bpf_fault_ops_ctx *ctx,
             unsigned char *buf)
{
    /* Allow all writes; buf contains current page contents */
    return 0;
}

SEC(".struct_ops.link")
struct fault_ops my_fault_ops = {
    .handle_page_fault = (void *)handle_page_fault,
    .handle_wp_fault = (void *)handle_wp_fault,
};
```

Not all callbacks need to be populated.  For missing-only mode,
`handle_wp_fault` may be NULL.  For WP-only mode, `handle_page_fault`
may be NULL (missing faults follow the normal kernel zero-fill path).

### BPF kfunc: bpf_fault_writeprotect()

Available to BPF struct_ops fault handlers:

```c
int bpf_fault_writeprotect(struct bpf_fault_ops_ctx *ctx,
                           __u64 start, __u64 len,
                           bool enable_wp);
```

Enables or resolves write-protection on a page range from within a BPF
callback.  This allows dynamic, fine-grained WP control (e.g., re-protect
a page after allowing a write).  Marked `KF_SLEEPABLE`; the mmap lock is
not held when BPF callbacks execute.

Returns 0 on success or a negative errno on failure.

## USERSPACE API

### Registration

```c
struct bpf_link *bpf_map__attach_fault_ops(const struct bpf_map *map,
                                           void *start, unsigned long len,
                                           unsigned int flags);
```

Registers a fault_ops BPF program on the virtual address range
[`start`, `start + len`).

**map**: The struct_ops BPF map containing the fault_ops callbacks.
    Must be of type `BPF_MAP_TYPE_STRUCT_OPS`.

**start**: Start of the virtual address range.  Must be page-aligned.

**len**: Length in bytes.  Must be page-aligned and non-zero.

**flags**: Registration flags (may be ORed together):

| Flag | Value | Description |
|------|-------|-------------|
| 0    | 0     | Missing fault mode (default) |
| `BPF_FAULT_FLAG_WP` | `1 << 0` | Write-protect mode |
| `BPF_FAULT_FLAG_INHERIT` | `1 << 1` | Inherit registration across fork |

Returns a `struct bpf_link *` on success.  On failure, returns an error
pointer; use `libbpf_get_error()` to extract the error code.

The link holds a reference to the registration.  Destroying the link
via `bpf_link__destroy()` unregisters the fault handler, clears VMA
flags, and resolves any outstanding write-protection.

### Multi-region management

After initial registration, additional memory regions can be added to
or removed from an existing link without creating new BPF programs:

```c
int bpf_link__fault_register(int link_fd, __u64 start, __u64 len);
int bpf_link__fault_unregister(int link_fd, __u64 start, __u64 len);
```

**bpf_link__fault_register()** adds a new region `[start, start+len)`
to the link.  The region inherits the fault mode (missing or WP) from
the original registration.  Re-registering the same region with the
same link is idempotent.

**bpf_link__fault_unregister()** removes a region from the link.
Subsequent faults in that region follow the normal kernel path (zero-
fill for missing, no intercept for writes).

Both take a raw link file descriptor (use `bpf_link__fd(link)` to
obtain it) and require page-aligned `start` and non-zero, page-aligned
`len`.  Under the hood, these use the `BPF_LINK_FAULT_OPS_CMD` syscall
command with `BPF_FAULT_REGISTER` or `BPF_FAULT_UNREGISTER` flags.

Alternatively, the raw syscall interface:

```c
union bpf_attr attr = {
    .link_fault_cmd = {
        .link_fd = bpf_link__fd(link),
        .flags   = BPF_FAULT_REGISTER,  /* or BPF_FAULT_UNREGISTER */
        .start   = (unsigned long)addr,
        .len     = length,
    },
};
int ret = syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &attr, sizeof(attr));
```

### Fork inheritance

When `BPF_FAULT_FLAG_INHERIT` is set at registration time, child
processes created via `fork()` inherit the bpf_fault registration.
The child receives a lightweight copy of the parent's fault context
that shares the same BPF struct_ops map (via `bpf_map_inc()`).

Key semantics:

- Each child gets an independent `bpf_fault_ctx` bound to its own
  `mm_struct`.  Faults in the child execute the same BPF program as the
  parent.
- The child does **not** automatically receive a link fd.  Its inherited
  context is cleaned up automatically when the child's mm is torn down
  (in `__mmput()`).
- The parent's link destruction does not affect inherited children —
  the BPF map is kept alive by the child's reference.
- Without `BPF_FAULT_FLAG_INHERIT`, fork strips `VM_BPF_FAULT` flags
  from child VMAs and the child gets normal zero-fill pages (existing
  behavior).

### Claiming an inherited context

After fork, the child can obtain a proper link fd for its inherited
context using `BPF_FAULT_CLAIM`:

```c
int bpf_link__fault_claim(int parent_link_fd);
```

**parent_link_fd**: The parent's link fd, inherited via the fd table.
The child still holds a file reference to the parent's `bpf_link`,
which is used to look up the matching inherited context by the
parent's link ID stored at fork time.

Returns a new fd on success, backed by a proper `bpf_link` with full
lifecycle management.  On failure, returns -1 with errno set.

Once claimed, the child can use the new fd for all link operations:
`BPF_FAULT_REGISTER`, `BPF_FAULT_UNREGISTER`, `BPF_FAULT_WP_ENABLE`,
`BPF_LINK_UPDATE`, and `close()`.  The inherited context transitions
from lightweight (no bpf_link) to fully managed (bpf_link lifecycle).

If the child never claims, existing behavior is preserved — faults
still work and the context is cleaned up on mm teardown.

After claiming, the child should `close()` the parent's link fd to
release the parent's file reference.

Alternatively, the raw syscall interface:

```c
union bpf_attr attr = {
    .link_fault_cmd = {
        .link_fd = parent_link_fd,
        .flags   = BPF_FAULT_CLAIM,
    },
};
int child_fd = syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD,
                        &attr, sizeof(attr));
```

### Write-protection control

```c
union bpf_attr attr = {
    .link_fault_cmd = {
        .link_fd = link_fd,
        .flags   = BPF_FAULT_WP_ENABLE,  /* or 0 to resolve */
        .start   = (unsigned long)addr,
        .len     = length,
    },
};
int ret = syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &attr, sizeof(attr));
```

Applies or removes write-protection on a page range previously
registered with `BPF_FAULT_FLAG_WP`.

**link_fd**: File descriptor of the fault_ops link.

**flags**: Control flags:

| Flag | Value | Description |
|------|-------|-------------|
| `BPF_FAULT_WP_ENABLE` | `1 << 0` | Apply write-protection |
| `BPF_FAULT_CLAIM` | `1 << 3` | Claim inherited context (returns new fd) |
| 0    | 0     | Resolve (remove) write-protection |

**start**: Start address.  Must be page-aligned.

**len**: Length in bytes.  Must be page-aligned.

When enabling WP, each present PTE in the range has the uffd-wp marker
bit set and write permission cleared.  Non-present PTEs get a
`PTE_MARKER_UFFD_WP` swap entry.  Subsequent writes to these pages
trigger WP faults dispatched to the BPF `handle_wp_fault` callback.

When resolving WP, the uffd-wp bits are cleared and write permission is
restored (if the VMA allows it).

Returns 0 on success, -1 on failure with errno set.

### Link update

The BPF program behind a fault_ops link can be atomically replaced via
`BPF_LINK_UPDATE` (using `bpf_link_update()` in libbpf).  The new
struct_ops map must define the same `struct fault_ops` type.  Active
faults in flight will complete with the old program; new faults dispatch
to the updated program.

### Teardown

```c
bpf_link__destroy(link);
```

Destroying the link:

1. Marks the context as released (in-flight faults retry without the
   BPF handler).
2. Clears `VM_BPF_FAULT` / `VM_BPF_FAULT_WP` flags on all registered
   VMAs.
3. Resolves any outstanding write-protection markers.
4. Releases the `bpf_fault_ctx` reference.

Teardown is safe with concurrent faults.  The `released` flag causes
in-flight handlers to return `VM_FAULT_RETRY`, and the kernel retries
the fault through the normal path.

## SUPPORTED MAPPING TYPES

bpf_fault supports the following VMA types:

| Mapping type | Missing mode | WP mode | Notes |
|-------------|:---:|:---:|-------|
| Anonymous private (`MAP_PRIVATE \| MAP_ANONYMOUS`) | Yes | Yes | Primary use case |
| Hugetlb (private and shared) | Yes | Yes | Requires huge-page-aligned boundaries |
| Shmem/tmpfs (private) | Yes | Yes | Pre-fills page from file content |
| Shmem/tmpfs (shared, `MAP_SHARED`) | No | No | Needs file rmap support |
| File-backed (ext4, xfs, etc.) | No | No | Not supported |

All registered VMAs must have `VM_MAYWRITE` set (the process must have
write permission to the backing store).

## TYPICAL USAGE PATTERNS

### Missing fault handler (userfaultfd replacement)

```c
/* 1. Load and attach */
struct my_ops_bpf *skel = my_ops_bpf__open_and_load();
void *region = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
struct bpf_link *link = bpf_map__attach_fault_ops(
    skel->maps.my_ops, region, size, 0);

/* 2. Access pages — each fault handled by BPF in-kernel */
for (size_t i = 0; i < num_pages; i++) {
    char c = ((volatile char *)region)[i * page_size];
    /* BPF handle_page_fault fills page, kernel installs PTE */
}

/* 3. Cleanup */
bpf_link__destroy(link);
my_ops_bpf__destroy(skel);
munmap(region, size);
```

### Write-protect dirty tracking

```c
/* 1. Load and attach with WP flag */
struct wp_ops_bpf *skel = wp_ops_bpf__open_and_load();
void *region = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
struct bpf_link *link = bpf_map__attach_fault_ops(
    skel->maps.wp_ops, region, size, BPF_FAULT_FLAG_WP);

/* 2. Populate pages (normal kernel zero-fill, no BPF intercept) */
for (size_t i = 0; i < num_pages; i++)
    ((volatile char *)region)[i * page_size] = 'P';

/* 3. Write-protect the region */
union bpf_attr wp = {
    .link_fault_cmd = {
        .link_fd = bpf_link__fd(link),
        .flags   = BPF_FAULT_WP_ENABLE,
        .start   = (unsigned long)region,
        .len     = size,
    },
};
syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &wp, sizeof(wp));

/* 4. Access pages — writes trigger BPF handle_wp_fault */
for (size_t i = 0; i < num_pages; i++)
    ((volatile char *)region)[i * page_size] = 'W';
/* BPF program can count, log, or selectively deny writes */

/* 5. Resolve WP when done tracking */
wp.link_fault_cmd.flags = 0;
syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &wp, sizeof(wp));

/* 6. Cleanup */
bpf_link__destroy(link);
```

### Multi-region (dynamic linker pattern)

```c
/* 1. Load BPF program once */
struct my_ops_bpf *skel = my_ops_bpf__open_and_load();

/* 2. Attach to the first library region */
void *lib1 = mmap(NULL, lib1_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
struct bpf_link *link = bpf_map__attach_fault_ops(
    skel->maps.my_ops, lib1, lib1_size, 0);

/* 3. Add additional library regions to the same link */
void *lib2 = mmap(NULL, lib2_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
bpf_link__fault_register(bpf_link__fd(link), (unsigned long)lib2,
                         lib2_size);

void *lib3 = mmap(NULL, lib3_size, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
bpf_link__fault_register(bpf_link__fd(link), (unsigned long)lib3,
                         lib3_size);

/* All regions share the same BPF program — no extra loads */

/* 4. Optionally remove a region */
bpf_link__fault_unregister(bpf_link__fd(link), (unsigned long)lib2,
                           lib2_size);
munmap(lib2, lib2_size);

/* 5. Cleanup destroys all remaining registrations */
bpf_link__destroy(link);
```

### Fork-inheritable registration

```c
/* 1. Register with INHERIT flag */
void *region = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
struct bpf_link *link = bpf_map__attach_fault_ops(
    skel->maps.my_ops, region, size, BPF_FAULT_FLAG_INHERIT);

/* 2. Fork — child inherits bpf_fault registration */
pid_t pid = fork();
if (pid == 0) {
    /* Child: faults on region execute the same BPF program */
    volatile char *p = (volatile char *)region;
    char c = *p;  /* BPF-processed page */
    _exit(0);
}

/* 3. Parent: continues using bpf_fault normally */
waitpid(pid, NULL, 0);
bpf_link__destroy(link);
```

### Fork + claim (child manages its own regions)

```c
/* 1. Register with INHERIT flag */
void *region = mmap(NULL, size, PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
struct bpf_link *link = bpf_map__attach_fault_ops(
    skel->maps.my_ops, region, size, BPF_FAULT_FLAG_INHERIT);
int parent_fd = bpf_link__fd(link);

/* 2. Fork */
pid_t pid = fork();
if (pid == 0) {
    /* Child: claim the inherited context */
    int child_fd = bpf_link__fault_claim(parent_fd);
    close(parent_fd);  /* release parent's file reference */

    /* Now the child has a proper link fd and can manage regions */
    void *extra = mmap(NULL, extra_size, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    bpf_link__fault_register(child_fd, (unsigned long)extra, extra_size);

    /* Use pages ... */

    close(child_fd);  /* proper cleanup via bpf_link lifecycle */
    _exit(0);
}

waitpid(pid, NULL, 0);
bpf_link__destroy(link);
```

## ERROR CODES

### bpf_map__attach_fault_ops()

| Error | Cause |
|-------|-------|
| `EINVAL` | Map is not `BPF_MAP_TYPE_STRUCT_OPS`; invalid flags; start/len not page-aligned; VMA type not supported; hugetlb alignment mismatch |
| `ENOMEM` | Memory allocation failure |
| `ENOENT` | No VMA found in the specified range |
| `EBUSY` | VMA already registered with a different bpf_fault context |
| `EPERM` | VMA lacks `VM_MAYWRITE` |

### BPF_LINK_FAULT_OPS_CMD

| Error | Cause |
|-------|-------|
| `EINVAL` | Link is not a fault_ops link; multiple flags set; start/len not page-aligned; zero length; WP enable on non-WP link |
| `ENOENT` | No matching VMA in the specified range; no inherited context matching the parent link (claim) |
| `EBUSY` | Region already registered with a different context (register) |
| `ENOMEM` | Memory allocation failure (claim) |
| `ESRCH` | Process mm no longer valid |

### Fault-time errors (delivered as signals)

| Signal | Cause |
|--------|-------|
| `SIGBUS` | BPF `handle_page_fault` or `handle_wp_fault` returned non-zero |
| `SIGBUS` | Missing fault on VMA with no `handle_page_fault` callback |
| `SIGSEGV` | Normal permission violation (unrelated to bpf_fault) |

## COMPARISON WITH USERFAULTFD

| Feature | bpf_fault | userfaultfd |
|---------|-----------|-------------|
| Fault handling context | In-kernel, faulting thread | Userspace handler thread |
| IPC per fault | None | poll + read + ioctl |
| Context switches per fault | 0 | 2 (to/from handler) |
| Missing fault support | Yes | Yes |
| Write-protect support | Yes (PTE-level) | Yes (PTE-level) |
| Minor fault support | No | Yes |
| SIGBUS mode | N/A (synchronous) | Yes |
| Fork inheritance | Yes (`BPF_FAULT_FLAG_INHERIT`) | Yes (event-based) |
| Event notifications (remap, remove) | No | Yes |
| Page content control | BPF fills kernel page | Handler copies via UFFDIO_COPY |
| Multi-threaded scalability | Scales with threads | Bottlenecked on handler |
| Handler language | BPF (verified, JIT'd) | Any (userspace) |
| Typical latency (p50, 4K pages) | ~7 us | ~200 us |

## COMPARISON WITH MPROTECT + SIGSEGV

For write-protect use cases only:

| Feature | bpf_fault WP | mprotect + SIGSEGV |
|---------|--------------|-------------------|
| Granularity | PTE-level | VMA-level |
| VMA splitting | None | Per-page mprotect splits VMAs |
| Resolution mechanism | Clear PTE bit | mprotect(PROT_READ\|PROT_WRITE) |
| Lock requirements | PTE lock only | VMA write lock per resolution |
| vm.max_map_count risk | No | Yes, at scale |
| Batch protect/resolve | Single syscall for range | Per-page mprotect calls |
| Handler context | In-kernel BPF | Signal handler |
| Typical latency (p50, 4K pages) | ~7 us | ~35 us |

## KERNEL CONFIGURATION

bpf_fault requires:

```
CONFIG_BPF=y
CONFIG_BPF_JIT=y
CONFIG_BPF_SYSCALL=y
CONFIG_DEBUG_INFO_BTF=y
CONFIG_USERFAULTFD=y
CONFIG_PTE_MARKER_UFFD_WP=y    (for WP mode)
CONFIG_BPF_FAULT=y
CONFIG_64BIT=y
```

`CONFIG_BPF_FAULT` depends on `USERFAULTFD`, `BPF_JIT`, and `64BIT`.

## LIMITATIONS

- **Missing + WP cannot be combined** on the same registration.  A
  single `bpf_map__attach_fault_ops()` call registers either missing
  or WP mode, not both.  A future `BPF_FAULT_FLAG_MISSING` flag will
  enable combined registrations.

- **Shared shmem not supported.**  `MAP_SHARED` tmpfs mappings cannot
  be registered because the file reverse-mapping (rmap) integration is
  not yet implemented.

- **Regular file-backed mappings not supported.**  Only anonymous,
  hugetlb, and private shmem VMAs can be registered.

- **No remap/remove event notifications.**  Unlike userfaultfd,
  bpf_fault does not deliver remap or remove events.  VMA operations
  (split, merge, mremap) are handled transparently by the kernel.
  Fork inheritance is supported via `BPF_FAULT_FLAG_INHERIT`.

- **No minor fault mode.**  userfaultfd's minor fault mode (page present
  but needs setup) is not available in bpf_fault.

- **Inherited contexts require an explicit claim.**  Child processes
  that inherit bpf_fault registrations via fork do not automatically
  receive a link fd.  The child must call `BPF_FAULT_CLAIM` to obtain
  a proper link fd for region management.  Without claiming, faults
  still work but the child cannot add/remove regions or control
  write-protection.  Unclaimed contexts are cleaned up automatically
  when the child exits.

- **Single context per VMA.**  A VMA can only be registered with one
  bpf_fault context at a time.  Attempting to register an already-
  registered VMA with a different context returns `EBUSY`.

- **64-bit only.**  bpf_fault is not available on 32-bit architectures.

- **Page size assumption in BPF programs.**  The `handle_page_fault`
  callback receives a `PAGE_SIZE` buffer.  BPF programs that hardcode
  4096 will break on architectures with different page sizes.  Use
  the page size from `bpf_fault_ops_ctx` or a runtime constant.

- **No userspace page source.**  Unlike `UFFDIO_COPY` which copies from
  a user-provided source buffer, bpf_fault's `handle_page_fault`
  operates on a kernel-allocated page.  The BPF program must generate
  content programmatically or read from BPF maps.

## SEE ALSO

userfaultfd(2), bpf(2), mprotect(2), libbpf(7)
