bpf_fault Use Cases
===================

Existing use cases: VM snapshot acceleration, lazy dynamic linker
relocations, electric fence, garbage collection write barriers.


Performance-motivated use cases
-------------------------------

These are feasible with userfaultfd but become practical with
bpf_fault because the kernel-to-userspace round-trip is eliminated.

1. Demand-paged decompression

   Keep cold data compressed in memory, decompress on fault. A database
   stores compressed page contents in a side structure; the BPF handler
   decompresses into the faulting page. WP faults detect dirty pages for
   re-compression. Application-controlled zswap without touching disk.

2. Software transactional memory write-set tracking

   Mark pages read-only at txn_begin(). WP faults build the write set
   and COW pages into private buffers. Commit or discard at txn_end().
   With userfaultfd, two context switches per faulting page makes STM
   slower than locks, defeating the purpose.

3. Distributed shared memory / far memory

   Fault on access to remote pages, fetch over RDMA/network. userfaultfd
   works here (post-copy live migration already uses it), but bpf_fault
   reduces fault latency for latency-sensitive DSM. Also useful for
   CXL memory tiering: periodically MADV_DONTNEED regions, measure
   re-access frequency via fault counts in BPF maps.

4. Unlimited software watchpoints

   x86 has 4 hardware watchpoints. WP-protect pages containing watched
   addresses; the BPF handler checks if the faulting address matches a
   watch list in a BPF map. Scales to arbitrary watchpoint counts.
   Practical for hot variables only with bpf_fault's inline handling.

5. COW snapshots for database MVCC

   WP-protect a mapped region at snapshot time. On write, the BPF
   handler COWs the original page to a snapshot buffer, then allows the
   write. Readers see the frozen snapshot. Zero upfront copy cost -- pay
   only for pages written during the snapshot's lifetime.

6. Lazy JIT compilation

   Map a large code region, compile methods on first execution. The BPF
   handler looks up which method lives at the faulting address and
   populates the page with compiled code. userfaultfd's single handler
   thread serializes compilation; bpf_fault handles faults in parallel.

7. Sparse structures with computed defaults

   Map a huge virtual region for a sparse array or matrix. The BPF
   handler initializes pages with a default pattern on first access.
   Only touched pages consume physical memory.

8. Record/replay deterministic debugging

   Periodically WP-protect shared pages, record thread ID and timestamp
   on each write fault for deterministic replay. With userfaultfd, the
   per-fault overhead makes recording 100-1000x slower, approaching
   ptrace territory.

9. MMIO interception for device emulation

   Intercept loads/stores to memory-mapped I/O regions for hardware
   emulation. Device registers are often polled in tight loops;
   userfaultfd's round-trip per access makes emulation orders of
   magnitude slower than hardware.

10. Transparent page encryption

    Decrypt pages on access, re-encrypt on eviction sweep. The BPF
    handler manages keys and can enforce access policies (e.g., only
    decrypt if the faulting instruction is in an approved code region).

11. Cooperative memory overcommit / balloon driver

    Under memory pressure, the BPF handler rejects faults (SIGBUS) or
    redirects to compressed backing stores, giving applications graceful
    degradation without OOM kills.


Library-oriented use cases
--------------------------

The use cases below exploit bpf_fault's structural advantages over
userfaultfd: no handler thread, no fd lifecycle management, no
signal handler conflicts, and composability in library code.


Why userfaultfd falls short for libraries
-----------------------------------------

userfaultfd requires a dedicated poll thread, which means:

- The library must own a thread (breaks single-threaded, pre-main,
  signal-handler, and async contexts).
- The handler thread must never touch the registered region (deadlock).
- Two libraries cannot independently use userfaultfd without
  coordinating the handler thread.
- The handler thread is visible to the application (shows up in
  /proc/pid/task/, receives signals, consumes a stack).

bpf_fault runs inline in the faulting thread's kernel context. No
thread, no fd, no signal handler. Libraries register regions and
attach BPF programs without any application cooperation.


Use cases
---------

1. Memory allocator page management (jemalloc, mimalloc, tcmalloc)

   An allocator library implements its own large-page strategy: maps
   2MB-aligned regions, faults in 4K pages on demand, collapses to huge
   pages based on allocation density. Allocators load before main(),
   can't assume pthreads, and can't introduce threads that might take
   locks or interact with the application's threading model.

2. COW in zero-copy IPC libraries (flatbuffers, Cap'n Proto)

   A zero-copy IPC library shares memory between processes. When a
   receiver mutates a shared buffer, WP faults trigger COW inline. The
   library is embedded in the application's event loop -- it can't own a
   thread and must work in async, single-threaded, and signal-handler
   contexts.

3. Guard pages / growable stacks in coroutine runtimes

   Fiber runtimes allocate thousands of small stacks, each needing a
   guard region. Currently they use mprotect + SIGSEGV, which is
   process-global and conflicts with sanitizers, debuggers, and JITs.
   bpf_fault delivers SIGBUS per-region with no signal handler, and can
   implement growable stacks by extending the mapping instead of
   crashing.

4. Dirty page tracking in embedded storage engines

   An embedded database (SQLite, RocksDB) WP-protects its mapped data
   pages to implement write-ahead logging. The engine is dlopen()'d --
   it can't spawn threads. The BPF handler logs old page contents to a
   WAL region before allowing the write.

5. Memory access profiling via LD_PRELOAD

   A preloaded profiler periodically write-protects regions and counts
   faults per page for hot/cold analysis, false sharing detection, or
   working set estimation. As a preloaded library, it cannot create
   threads or install signal handlers (conflicts with the target
   application, sanitizers, JIT). The BPF program tallies accesses in a
   map; the profiler reads the maps on demand.

6. Transparent page encryption in sandboxing shims

   A library implementing a userspace enclave (SGX SDK runtime, WASM
   sandbox) decrypts pages on access and re-encrypts on eviction. The
   shim must be invisible to the application: no threads, no signal
   handlers, no fds the application might close.

7. Application-level checkpoint/rollback

   A library providing checkpoint()/rollback() (speculative execution,
   database savepoints, game state) WP-protects the address space and
   COWs pages on write. With userfaultfd, the handler thread must avoid
   touching checkpointed memory -- nearly impossible if it calls malloc
   on the same heap. bpf_fault handlers run in kernel context and access
   BPF maps, not userspace heap, eliminating this deadlock class.
