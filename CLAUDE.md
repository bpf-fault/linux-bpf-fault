# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working
with code in this repository.

## Repository Overview

This is a Linux kernel source tree hosting the **writeback redesign**
research project — replacing the cubic-polynomial / proportional-share
dirty-page throttling in `mm/page-writeback.c` with a PI controller plus
a two-constraint (time-based + memory-ceiling) dirty limit. The work is
staged for a research paper first, upstream RFC later.

## Branch Layout

- **`wb`** — primary working branch. Kernel changes for the writeback
  redesign land here. Started at pristine v6.19 and will accumulate the
  multi-timescale estimator, PI controller, two-constraint setpoint,
  and related tracepoint infrastructure.
- **`wb-base`** — pristine upstream `v6.19`, kept unmodified as a
  baseline reference for A/B comparison. Do not add feature code here;
  its purpose is to reproduce stock behavior exactly.
- **`main`** — unrelated bpf_fault work (BPF struct_ops page fault
  handler). Ignore for the writeback project.
- **`bpf-fault-folio-noretry`**, **`base`**,
  **`experiment/semcode-ablation`** — other experimental tips, ignore.

When working on writeback, stay on `wb` (this is the "new main" for
the project). Use `wb-base` only to produce the baseline kernel for
benchmarks.

## Kernel Build

Two kernels are built from this tree during the project:

- **`6.19.0-wb-baseline`** — built from the `wb-base` branch
  (pristine v6.19 + the config fragment in `build.py`). Used as the
  stock baseline for all hardware benchmarks.
- **`6.19.0-wb-pi`** — built from the `wb` branch (writeback
  redesign). The new controller replaces the cubic + step filter;
  same config fragment, same tooling.

Both install side-by-side in `/boot` and are switched via grub entries.

Use the `build.py` helper — it applies the writeback config fragment
automatically (brd, dm-delay, PSI, BLK_WBT, CGROUP_WRITEBACK, MEMCG,
and BPF dev options):

```bash
./build.py build               # build with clang (default)
./build.py build --no-clang    # build with gcc
./build.py build --debug       # adds DEBUG_KERNEL/LOCKDEP/etc.
./build.py install             # build + modules_install + install (sudo)
```

Or plain make if you want to skip the config munging:

```bash
make LLVM=1 CC=clang -j$(nproc)                           # build
make LLVM=1 CC=clang modules_install INSTALL_MOD_STRIP=1  # sudo
make LLVM=1 CC=clang install                              # sudo
```

For boot-testing use `vng` (virtme-ng) via the `virtme-ng` /
`build-and-boot` skills rather than installing on the host. The
`kernel-build` and `virtme-ng` skills are already available and cover
config fragments, ccache, and serial-console capture. The
writeback-project-specific vng harness lives at
`/mydata/wb-work/phase0/vng-experiments/launch-vng.sh` and sets up a
4 GB guest with a 30 MB/s QEMU-throttled virtio-blk for the cliff /
idle-reset / many-writers experiments.

## Project Layout Outside the Kernel

- `/mydata/wb-work/` — benchmark harnesses, simulator, and results
  - `phase0/` — hardware benchmarks (W1..W9 workloads, sweeps, vng
    experiments)
  - `phase1/wb_sim/` — Python simulator (controller, plant, scenarios)
- `/mydata/linux-wb/SESSION.md` — living session progress file. **Read
  it first at the start of any writeback session.** Covers completed
  work, current state, design decisions, and the post-reboot resume
  checklist.
- `/mydata/linux-wb/wb-plan.md` — full implementation plan v2, with
  scenarios and extensions.

## Kernel Workflow Conventions

- Coding style: `Documentation/process/coding-style.rst` (tabs, 80-col
  soft limit, K&R). Run the `checkpatch` skill on changes before
  proposing commits.
- AI-assisted contributions: include `Assisted-by: Claude:claude-opus-4-6`
  in the trailer. Do **not** add `Signed-off-by` (only humans certify
  the DCO) and do **not** add `Co-Authored-By` to kernel commits. See
  `Documentation/process/coding-assistants.rst`.
- For patch review (lore URLs, message-ids, series on a branch) use the
  `kreview` / `kseries` / `lore-reviewer` skills; for debugging
  crashes use `kdebug`; for boot-and-test-after-edit cycles use
  `build-and-boot`.
- `semcode` is git-aware — queries default to the current commit, but
  pass `branch="wb-base"` when you need to inspect the pristine
  behavior without switching branches, or `branch="main"` for bpf_fault.
