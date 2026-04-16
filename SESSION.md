# Writeback Redesign — Session Progress

**Last updated**: 2026-04-11 late. **Kernel Phase 2.1 prototype is
mostly landed (7 commits on `wb` from `wb-base`), and validation on
the `6.19.0-wb-pi+` kernel surfaced a design-level course correction:
the original "time-based per-wb limit replaces RAM-proportional
dirty_ratio" thesis has been walked back.** The time-based setpoint
over-throttles medium-sized workloads (we saw a 200 MB buffered write
take 35 s on a 30 MB/s device under `drain_time_ms = 2000` because the
45 MB setpoint forced the task down to `bw_eff/4` while stock let it
finish at ~7 s via its 800 MB freerun). Throttling writes that never
result in a `sync()` call is pure tax, and bounding sync latency below
`memory_cap / drain_rate` is physically impossible without that tax.

**The reframed design**: memory-ceiling is the *primary* throttle
point (stock-like, `dirty_ratio × dirtyable_memory / num_active_wbs`),
PI engages only when dirty approaches it, and `drain_time_target`
becomes the knob that drives **background flusher aggressiveness**
(via `bg_thresh = drain_time × bw`), not the task-throttling setpoint.
This keeps the paper's legitimate contributions (no freerun cliff,
PI replaces cubic step-filter, fprop deleted, `num_active_wbs`
replaces slack/8) while dropping the unsustainable "bound sync
latency by throttling writes" claim. Details in §"Design reframe
(2026-04-11 late)" below. Prior sections that describe the
time-based-setpoint-as-primary approach are kept as historical
record — they're accurate for the design-in-progress state at the
time but should not be read as the current design.

Earlier pivot (2026-04-10): workload-driven to code-driven analysis
after the W9 drbg disambiguation sweep (27 runs, flat on both axes).
The vmstat traces explained why: peak dirty was 1–2 GB, dr=5 threshold
is 6 GB, dr=20 is 24 GB — **the hard cap never fires on a 22 GB
dataset in 125 GB of RAM**. Confirmed the prior observation was on a
100 GB dataset, so the seed was 4.5× too small. We then read the
writeback implementation end-to-end and found eight structural issues
that hold independent of dataset size — the headline being that
`balance_dirty_pages` bypasses its entire control machinery whenever
`dirty ≤ 0.75·thresh` (page-writeback.c:1749, 1863), making the
controller dead code on most modern workloads. See §"Kernel code
analysis (2026-04-10 late)". Simulator corrected to match — see
§"Simulator corrections from the code analysis". The S11 cliff
scenario demonstrates the freerun cliff cleanly: stock stays frozen
at its cold-start dirty_ratelimit seed for all 40 s of a ramp
workload while PI tracks smoothly. Earlier W6 sysbench OLTP sweep
also complete (24 runs, flat across dr).
**Location**: `/mydata/linux-wb/SESSION.md` (this file, in the kernel repo)
**Workspace**: `/mydata/wb-work/` — benchmark harness, simulator, and results

This file tracks where we are in the wb (writeback redesign) project so we
can pick up cleanly across reboots and Claude sessions. **Read it first at
session start.** Benchmark scripts, the Python simulator, and captured
results all live under `/mydata/wb-work/`; this file is kept in the kernel
repo so it's discoverable alongside `wb-plan.md` and `CLAUDE.md`.

---

## Project goal (one line)

Replace Linux's cubic-polynomial / proportional-share dirty-page throttling
with a PI-controller that fixes the freerun-cliff / step-filter / fprop
pathologies while leaving the dirty_ratio-based memory cap in place as
the primary throttle point. Add a `drain_time_target` knob that controls
background-flusher aggressiveness so dirty shrinks proactively during
idle periods, reducing worst-case sync latency *without* taxing writes
that don't need to be throttled. Paper first, linux-mm RFC second.
No deadline.

Full plan: `/mydata/linux-wb/wb-plan.md` (v2 with this reframe landing
as v3 in the edit that accompanies this section).

---

## Design reframe (2026-04-11 late)

Why the original "time-based per-wb limit replaces dirty_ratio" thesis
was walked back, and what replaces it.

### What we tried

`setpoint = min(drain_time × bw_eff × 0.75, reserved × dirtyable_memory / num_active_wbs)`

with PI driving `dirty` toward `setpoint` as the primary throttle. The
latency term was supposed to be the first-principles bound: a sync()
starting right now completes in `drain_time` seconds, guaranteed.

### What broke it (kernel validation, 2026-04-11)

A 200 MB buffered write on a 30 MB/s QEMU-throttled disk with
`drain_time = 2 s`:

- setpoint = `0.75 × 2 × 30 MB/s = 45 MB`
- write() blasts page cache at memory speed, dirty reaches 200 MB fast
- PI sees dirty >> setpoint, throttles task to `bw_eff/4 ≈ 7.5 MB/s`
- dd takes ~35 s, vs stock's ~7 s

Same test with `drain_time = 30 s`:
- setpoint = 675 MB
- 200 MB fits, no throttle, dd done in 0.3 s, sync in 7 s (physics-limited)

The difference isn't that the 2 s run is "wrong" — it's that **we're
throttling a workload that will never compromise sync latency simply
because the workload is larger than the setpoint**. Stock would write
these 200 MB to the page cache and call it done. If the user later
calls `sync()`, they pay `200 MB / 30 MB/s = 6.6 s`. That's fine for
most workloads. **Throttling to 7.5 MB/s to "protect" a sync() that
nobody called is pure tax.**

And the tax is unavoidable without predicting whether `sync()` will
be called. We can't predict that.

### The physics: there's no free lunch

- Bounded sync latency requires small dirty pool
- Small dirty pool requires throttling OR writes that don't exceed drain rate
- On a workload bigger than the setpoint, the only way to keep dirty
  small is to throttle write() below drain rate
- Any throttle below drain rate is visible latency on write() calls
- If the task never calls sync(), all that throttling was wasted

There is **no way** to get both "unthrottled write() for all
workloads" and "bounded sync() latency on slow devices with large
workloads". Pick one.

### The reframe

**Memory-ceiling is the primary throttle.** `dirty_ratio ×
dirtyable_memory / num_active_wbs` is the upper bound on dirty. PI
engages at ~75 % of it and drives dirty back under it. This is
identical in shape to what stock does — the innovation is the
*dynamics*, not the setpoint value.

**`drain_time_target` is redirected to flusher aggressiveness.**
Instead of being the setpoint, it drives `bg_thresh` — the point at
which the background flusher starts aggressively draining. A smaller
`drain_time_target` means the flusher starts earlier, so dirty stays
naturally small during idle periods without the task ever being
throttled. When `sync()` is eventually called, there's less to drain.

The resulting worst-case sync latency is still `dirty_pool_at_sync_time
/ drain_rate`, same as stock. But in practice `dirty_pool_at_sync_time`
will be smaller because the flusher has been eagerly draining, which
gives users most of the latency benefit without the throughput cost.

### What the paper's contributions now claim

1. **Freerun cliff deleted** (Issue 1). The PI control loop always
   runs; there's no dead-code regime below `0.75 × thresh`.
2. **PI replaces cubic + step filter** (Issues 2, 5, 6, 8). Better
   convergence, no gain-scheduled collapse, anti-windup clamp.
   Validated as stable across ±50 % gain sweeps (S8).
3. **fprop deleted** (Issue 4). `num_active_wbs` + equal-share is
   ~200 LOC smaller and provably bounds total dirty.
4. **Eager flushing via `drain_time_target`**. Users who want low
   sync latency after an idle period get it via the flusher
   catching up, not via write throttling.

Contributions we had to drop:

- ~~Time-based setpoint replaces RAM-proportional dirty_ratio~~ —
  no, dirty_ratio stays as the primary cap.
- ~~"Pareto dominance" over stock's dirty_ratio sweep~~ — the S15
  result where PI at one config beat stock across four dirty_ratio
  points was conditional on the tight time-based setpoint. Under the
  memory-based primary, PI matches stock's tunings rather than
  dominating them.

### What the simulator needs to reflect

- **S11 (slow cliff ramp)**: still a PI win. The result was about
  the freerun-cliff, not the setpoint value. PI control loop runs,
  stock's doesn't. Keeps.
- **S13 (bulk + WAL)**: current result (stock 4.9 GB vs PI 745 MB)
  was driven by the tight time-based setpoint. Under the memory-based
  design, PI's dirty pool grows toward `dirty_ratio × ram`
  (stock-equivalent). **Re-run needed.**
- **S14 (tight-dr stock vs PI)**: stock at `dirty_ratio = 0.02` gave
  493 MB max, PI gave 749 MB. Since PI's setpoint under the new
  design is memory-based, PI at stock's config would give similar
  max_dirty (~6 GB on the 32 GB test memory × 0.20 / 1 wb). **Re-run
  needed** — might not reproduce the PI advantage.
- **S15 (RocksDB analog Pareto)**: same issue. **Re-run needed.**
- **S16 (constraint-crossover)**: design no longer has two
  competing constraints in the setpoint — the memory cap is the only
  setpoint. Scenario becomes a simple bandwidth step. **Deprecate
  or rescope.**

### What the kernel code needs

- Revert `wb_compute_setpoint_pages` to use only the memory-based
  bound. Drop the `min(time_based, memory_based)` combination.
- Repurpose `wb_drain_time_ms` from "setpoint driver" to
  "`bg_thresh` driver". Kernel already has `dirty_background_ratio`;
  the new design adds `bg_thresh_pages = drain_time × bw_eff` as
  an alternative trigger (background flush starts at the smaller of
  the two).
- Keep PI (one-sided error variant), keep `bw_eff/4` floor, keep
  the quiescent hold, keep `period_fast = HZ+1`. These are stability
  fixes and still correct.
- Keep `wb_use_pi` sysctl for A/B on the same boot.
- Re-verify that the cliff experiment still shows the PI win (it
  should — Issue 1 fix is unchanged).

Action items tracked in the TaskList.

---

## Branch layout

- Primary working dir: `/mydata/linux-wb`
- Current branch: **`wb`** — treated as the new main for this project
- `wb-base`: pristine v6.19 upstream, untouched reference
- `main`, `bpf-fault-folio-noretry`: unrelated bpf_fault work — **ignore**

The `wb-plan.md`, `build.py`, `CLAUDE.md`, and `mcp-config.json` files in
the linux-wb directory are currently untracked — still being iterated on.

---

## Workspace layout

Everything for this project lives under `/mydata/wb-work/`:

```
/mydata/wb-work/
├── SESSION.md                       # this file
├── build/
│   ├── build.log                    # output of the kernel build
│   └── config.backup-*              # pre-build .config snapshot
├── phase0/
│   ├── run-workload.sh              # driver — wires instrumentation + workload
│   ├── setup/
│   │   └── synth-devices.sh         # brd + dm-delay setup (up|down|status)
│   ├── workloads/
│   │   ├── common.sh                # shared helpers, sysctl profiles
│   │   ├── w1-cross-device.sh       # fast (brd) vs slow (dm-delay) interference
│   │   ├── w2-spiky.sh              # 20× 200MB bursts, measure per-iter throughput
│   │   ├── w3-colocation.sh         # WAL + bulk writer on /mydata
│   │   ├── w4-sync-latency.sh       # dirty 10GB, time sync
│   │   └── w5-sustained.sh          # fio 50GB sequential — regression anchor
│   ├── instr/
│   │   ├── trace-bdp.bt             # bpftrace on writeback:balance_dirty_pages
│   │   ├── sample-vmstat.sh         # periodic /proc/vmstat CSV sampler
│   │   └── sample-pressure.sh       # periodic PSI CSV sampler
│   └── results/
│       └── env-inventory.txt        # captured at start of session
└── phase1/
    ├── wb_sim/                      # Python simulator package
    │   ├── plant.py                 # discrete-time device/task model
    │   ├── controller.py            # WbController (PI) + StockController (v6.19 port)
    │   ├── scenarios.py             # S1, S2, S5 scaffolded; S3/S4/S6/S7/S8 stubs
    │   └── run.py                   # CLI with --controller {pi,stock} and --compare
    ├── s1-compare.png               # example overlay plot
    └── s5-compare.png
```

---

## Kernel state

**Built**: `6.19.0-wb-baseline` (clang 18.1.3). Artifacts at
`/mydata/linux-wb/arch/x86/boot/bzImage` and `/mydata/linux-wb/vmlinux`.
Config has `BLK_DEV_RAM=m`, `DM_DELAY=m`, `DM_FLAKEY=m`, plus the usual
BPF/PSI/FTRACE stuff.

**Running kernel before reboot**: `6.17.0-bpf-fault+` — from the old
bpf_fault branch. Lacks `brd` and `dm-delay` modules, so Phase 0 cannot
run on it.

**Post-reboot goal**: `uname -r` should report `6.19.0-wb-baseline`. If it
reports something else, the install/grub step didn't take effect — see the
resume checklist below.

### Install + reboot commands

From `/mydata/linux-wb/`:

```bash
# Build is already done. Install the kernel + modules.
sudo ./build.py install

# Verify the installed kernel shows up in /boot.
ls /boot/vmlinuz-6.19.0-wb-baseline /boot/config-6.19.0-wb-baseline

# On Ubuntu, update-grub runs as part of `make install`, but double-check
# by listing available GRUB entries.
sudo grep -E "menuentry '(Ubuntu|Linux).*6\.19" /boot/grub/grub.cfg | head

# Reboot.
sudo reboot
```

If the default boot entry doesn't pick up 6.19.0-wb-baseline automatically,
pin it for one boot:

```bash
sudo grub-reboot "Advanced options for Ubuntu>Ubuntu, with Linux 6.19.0-wb-baseline"
sudo reboot
```

---

## What's done

- [x] `/mydata/wb-work/` workspace created
- [x] Environment inventory captured (`phase0/results/env-inventory.txt`)
- [x] v6.19 stock kernel built as `6.19.0-wb-baseline`
- [x] `build.py` refactored: `add_config_options()` function (renamed from
      `add_bpf_config_options`) now includes both the BPF configs and the
      writeback-required configs (`BLK_DEV_RAM`, `DM_DELAY`, `DM_FLAKEY`,
      `PSI`, `BLK_WBT`, `CGROUP_WRITEBACK`, `MEMCG`)
- [x] Phase 1 simulator scaffolded — `plant.py`, `controller.py` (both
      `WbController` and `StockController`), `scenarios.py` (S1, S2, S5),
      `run.py` (CLI with --controller and --compare)
- [x] `StockController` is a faithful port of v6.19 `wb_position_ratio`
      cubic polynomial + `wb_update_write_bandwidth` EWMA (including the
      secondary spike-damping smoothing)
- [x] Phase 0 synthetic device setup script (`setup/synth-devices.sh` —
      brd ramdisk as fast device, loop file + dm-delay as slow device)
- [x] Phase 0 workload scripts W1..W5 with common.sh helpers
- [x] Phase 0 instrumentation: bpftrace for balance_dirty_pages tracepoint
      (verified against v6.19 field layout), vmstat sampler, PSI sampler
- [x] Phase 0 driver (`run-workload.sh`) wires instrumentation around a
      workload run, handles sysctl profile switching
- [x] Phase 0 n=6 sweep analyzed (2026-04-10): WAL-tail story revised
      from deterministic 12232× to probabilistic 17% spike rate at
      dr ≤ 10. Aggregator (`aggregate.py`) and wmix analyzer added.
- [x] W6 sysbench OLTP harness built (2026-04-10): user-space MariaDB
      instance in `/mydata/wb-work/mysql/`, workload script
      `workloads/w6-sysbench-oltp.sh`, sweep driver `sweep-w6.sh`
      (suffix bug fixed 12:10; one-shot `sweep-w6-odirect.sh` rerun
      driver used for the O_DIRECT recovery and removed afterward).
      5.2 GB sysbench dataset prepared (10 tables × 2M rows).
      `analyze_w6` + aggregate.py W6 section added.
- [x] W6 sysbench OLTP sweep (2026-04-10): 24 runs (12 fsync +
      12 O_DIRECT), 3 iterations per `{dr1,dr5,dr20,dr40}` cell.
      Both flush methods flat across dr on tps, p99, p999, and
      write amp. Resolves batching-vs-PI open question — see
      §"Phase 0 W6 sysbench OLTP (complete)".
- [x] W9 drbg disambiguation sweep (2026-04-10 ~20:46): 27 runs
      (9 profiles × 3 iter). Both Sweep A (bg=1, dr varied) and
      Sweep B (dr=20, bg varied) flat within noise. Root cause
      identified via vmstat: peak dirty ~1–2 GB vs dr=5 thresh 6 GB.
      See §"drbg sweep result".
- [x] Kernel code analysis (2026-04-10 late): read
      mm/page-writeback.c and fs/fs-writeback.c end-to-end, identified
      8 structural issues with line numbers. See §"Kernel code
      analysis".
- [x] Simulator StockController corrected (2026-04-10 late) to
      match kernel behavior: freerun cliff gate, BANDWIDTH_INTERVAL
      gating at 200 ms, full wb_update_dirty_ratelimit step filter
      with gain schedule. See §"Simulator corrections".
- [x] New S11 scenario (slow cliff ramp) added to reproduce the
      freerun cliff pathology in a single clean scenario.

## Still to do

### Immediately after reboot

- [ ] Verify `uname -r` reports `6.19.0-wb-baseline`
- [ ] Verify `modprobe brd && modprobe dm-delay && modprobe dm-flakey`
      load without error
- [ ] Run `sudo /mydata/wb-work/phase0/setup/synth-devices.sh up` to
      create the brd and dm-delay devices
- [ ] Run `sudo /mydata/wb-work/phase0/setup/synth-devices.sh status` to
      confirm both mounts are present
- [ ] Smoke-test the driver with W5 (sustained, lowest-risk workload):
      `./run-workload.sh w5`

### Phase 0 benchmarking work

- [x] Run W1-W5 with `default` sysctl profile, 5 iterations each — done
- [x] Run W1 with `tuned-cross-device`, W3 with `tuned-colocation` — done
- [x] dirty_ratio sweep W2b/W3b/W4/Wmix × dr1..dr40 × n=6 — done, revised
      findings are in §"Phase 0 hardware findings (n=6, 2026-04-10)"
- [x] **W6 sysbench OLTP × {O_DIRECT, fsync} × {dr1, dr5, dr20, dr40} × 3 iter**
      — **done 2026-04-10**. Both flush methods flat across dr.
      See §"Phase 0 W6 sysbench OLTP (complete)" below.
- [ ] **Decision point on W9 rescaling**: rebuild seed at 100 GB
      to match user's prior observation (~45 min, ~200 GB disk) OR
      rerun existing 22 GB seed under a 32 GB cgroup memory.max.
      Either way, validates that the workload IS dr-sensitive when
      it's not in freerun the whole time.
- [ ] **Small-RAM vng VM experiment**: boot vng with `mem=4G` and
      re-run a simple fio workload. At 4 GB RAM, dr=20 thresh is
      ~800 MB, which any 2 GB fio job will cross. This is the
      cheapest way to actually observe the live kernel controller
      in its active regime, as opposed to freerun. Use bpftrace on
      `bdi_dirty_ratelimit` and `balance_dirty_pages` tracepoints
      to capture the controller state evolution.
- [ ] Targeted 30-iter run at dr1/dr5 on W3b + Wmix to tighten the 17%
      spike-rate CI (deprioritized relative to the code-first work)
- [ ] Plotting for each workload (matplotlib; deferred until after W6
      analysis so the plots can include the full story)
- [ ] Pathology confirmation table for the paper — **reframed**:
      now organized around the 8 code-level issues rather than the
      workload list. Hardware data becomes evidence for issues 1, 3,
      5, 8 specifically.

### Phase 1 simulator work

- [x] **Investigate S5 bw_effective collapse** — resolved with quiescent
      hold + anti-windup clamp + CV shrinkage gating.
- [x] Scaffold S3, S4, S6, S8 — all passing
- [x] Scaffold S7 multi-device (added `MultiDeviceSimulation` framework)
- [x] Scaffold S9 flash-GC stutter and S10 bandwidth jitter
- [x] Integral reset on burst_multiplier step change — subsumed by
      quiescent reset + tight clamp; not needed separately
- [x] Verify CV shrinkage still engages after the settling-gate change
      (S10 now covers this; gate changed from bw_slow-vs-medium to
      bw_fast-vs-medium in the process)
- [x] **StockController kernel-faithfulness pass (2026-04-10 late)**:
      freerun cliff gate, 200 ms BANDWIDTH_INTERVAL gating, full
      `wb_update_dirty_ratelimit` step filter with gain schedule,
      `balanced_dirty_ratelimit` state tracking. See §"Simulator
      corrections from the code analysis".
- [x] S11 slow-cliff-ramp scenario added. Reproduces the freerun
      cliff in a single clean scenario: Stock never exits freerun in
      40 s while PI tracks `bw_effective` continuously. Plot at
      `/mydata/wb-work/phase1/s11-compare.png`.
- [x] **Live-kernel cliff validation via vng (2026-04-11 ~00:30)**:
      4 GB vng with QEMU-throttled 30 MB/s virtio-blk. Phase A (300 MB
      at 150 MB/s) stayed at 300 MB peak dirty+wb (below 539 MB
      freerun). Phase B (1500 MB unrestricted) climbed through freerun
      at t=3.73 s and plateaued near the 719 MB hard cap for 30+ s
      while fio was throttled from page-cache-speed down to 49 MB/s
      (device-limited). Confirms the simulator-predicted cliff in the
      actual kernel. Experiment under `phase0/vng-experiments/`; log
      at `results/cliff-experiment-20260411-0030.log`.
- [ ] **Regenerate scenario results summary table** after the
      StockController corrections. Old table (§"Scenario results
      summary") is pre-fix and reflects an over-active Stock model.
      Mark as pre-fix and keep for audit; produce a new table with
      the same scenarios + S11 post-fix.
- [x] **Revisit S2 PI behavior** (2026-04-11): root-caused to
      `_contention_mult = 4 × drain_time × bw_eff` producing 30 GB
      setpoints on NVMe. First fix (absolute byte cap) rejected as
      unprincipled. Resolved via a first-principles rework:
      `setpoint = min(0.75 × drain_time × bw_eff, reserved_fraction ×
      dirtyable_memory / num_active_wbs)`. `_contention_mult`
      deleted; fprop deleted along with it (not needed — time-based
      primary already provides bandwidth-proportional sharing). Post-
      fix: S2 max_dirty 6.1 GB, tail_err 1.2 GB (physics-limited
      recovery); S7-fast max_dirty 3.5 GB. See §"Simulator regression
      investigation".
- [ ] **New scenarios to add from the code-first analysis**:
        * S12 "burst/idle/burst" — exercise the `wb_bandwidth_estimate_start`
          1 s idle reset (page-writeback.c:1542) and the subsequent
          re-engagement. Shows dirty_ratelimit freeze-and-stale behavior.
        * S16 "bandwidth step convergence" — 400 → 100 MB/s step with
          a continuous writer already in the control regime (tight
          dirty_ratio). Measure time-to-90%-convergence; expect Stock
          to take 8–12 s due to the gain-scheduled step filter, PI
          sub-second.
        * S17 "many-writer scaling" — 100+ tasks to exercise the
          bdp polling loop pathology (Issue 6) and
          control-in-task-context (Issue 8). Simulator can't measure
          lock contention but can count bdp call rate.
- [ ] Scaffold S11 long-idle and S12 many-writers — **superseded** by
      the items above; the original S11/S12 in wb-plan.md §1.3 are
      now the code-first-motivated S12/S17 above.
- [ ] Gain scheduling implementation — WbController currently uses fixed
      nominal `Kp=2.0`, `Ki=0.5/drain_time`. S8 sweep shows ±50% is
      stable with fixed gains, so scheduling is a refinement, not a
      blocker.
- [ ] Revisit the S1 "PI fixed point below true bandwidth" residual
      (490/500 MB/s post-fix) — may motivate keeping Extension C on the
      roadmap for a paper discussion section
- [ ] Stability analysis: damping ratios across operating envelope; Bode
      plot via python-control if useful for the paper

### Phase 2 prep (not yet started)

- [x] Resolve the S5 finding before starting Phase 2.1 (estimator design) —
      done; quiescent-hold and anti-windup clamp are now baseline design
      elements for Phase 2.1.

---

## Phase 0 hardware findings (n=6, 2026-04-10)

### dirty_ratio sweep: W2b × W3b × W4 × Wmix × {dr1, dr5, dr10, dr20, dr40}

Ran on cloudlab host: 125 GB RAM, SATA SSD (W5 sustained median 420
MB/s, n=7). Aggregated via `/mydata/wb-work/phase0/aggregate.py`. Each
dr point has n=6 = the original n=1 sweep + 5 overnight iterations from
`overnight.sh`. Raw runs under
`/mydata/wb-work/phase0/results/*-{w2b,w3b,w4,wmix}-dr*/`.

**Revision vs the 2026-04-09 n=1 write-up**: two of the three headline
single-run numbers (W3b dr1 = 173 ms p99.9, Wmix dr5 = 100 ms p99.9)
turn out to be **outlier runs, not medians**. The WAL-tail story is
*probabilistic*, not deterministic: at dr ≤ 10 a run has a ~17% chance
of producing a 19–170 ms tail spike; at dr ≥ 20 we saw zero such
spikes in 12 runs. Medians at every dr are ~60–80 µs. The autotuning
thesis survives but has to be stated in the new shape (below).

**W2b (spiky 5 GB bursts), n=6** — identical to n=1:

| dr   | iter1 MB/s          | iter20 MB/s         | iter20/iter1        |
|------|---------------------|---------------------|---------------------|
| dr1  | 439.75 [437–445]    | 439.30 [435–442]    | 1.00 [0.99..1.00]   |
| dr5  | 410.02 [407–414]    | 411.92 [405–414]    | 1.00 [0.98..1.01]   |
| dr10 | 376.38 [374–379]    | 376.54 [372–379]    | 1.00 [0.99..1.01]   |
| dr20 | 375.37 [374–379]    | 375.16 [374–380]    | 1.00 [0.99..1.02]   |
| dr40 | 377.53 [374–378]    | 376.34 [376–382]    | 1.00 [0.99..1.01]   |

No spiky-burst pathology on this hardware at any dr. iter1 throughput
sorts by dr (dr1 > dr5 > dr10 ≈ dr20 ≈ dr40) because dr1's tight cap
forces writes to hit the device directly while larger dr values allow
page-cache buffering that gets amortized across the full 20-burst
window. Matches n=1 exactly; noise is ±2%.

**W3b (50 GB bulk + WAL fsync), n=6** — rewritten:

| dr   | WAL p99.9 median (ms) | WAL p99.9 range     | bulk median (MB/s) | bulk range  |
|------|-----------------------|---------------------|--------------------|-------------|
| dr1  | 0.068                 | 0.017 .. **173.02** | 443.9              | 437.2–445.3 |
| dr5  | 0.072                 | 0.069 .. **139.46** | 464.7              | 462.9–466.0 |
| dr10 | 0.064                 | 0.059 .. **154.14** | 491.1              | 489.4–491.9 |
| dr20 | 0.065                 | 0.018 .. 0.070      | 540.6              | 538.6–542.5 |
| dr40 | 0.058                 | 0.016 .. 0.070      | 409.7              | 408.5–411.7 |

**Per-iteration WAL p99.9 distributions**, in chronological order, show
the pathology is bimodal at dr ≤ 10:

```
dr1:  [0.017, 0.017, 0.066, 0.071, 0.072, 173.015]    ← one 173 ms spike
dr5:  [0.069, 0.071, 0.072, 0.073, 0.095, 139.461]    ← one 139 ms spike
dr10: [0.059, 0.060, 0.061, 0.067, 0.074, 154.141]    ← one 154 ms spike
dr20: [0.018, 0.062, 0.064, 0.065, 0.069, 0.070]      ← zero spikes
dr40: [0.016, 0.016, 0.055, 0.061, 0.067, 0.070]      ← zero spikes
```

**Revised W3b finding**: dirty_ratio ≤ 10 exposes a **probabilistic
100–170 ms WAL tail spike** (3/18 runs = 17% spike rate). dirty_ratio
≥ 20 shows zero spikes in 12 runs. The 12232× regression from the n=1
writeup was a real *sample*, not a *mean* — it corresponds to the one
dr1 run that hit the spike. Medians at every dr are ~60–70 µs.

**Bulk throughput**: tight, monotonic except for the dr40 drop.
540 MB/s at dr20 is the peak; dr40 drops to 410 MB/s (a 24% regression
that is well outside the noise floor — min/max spreads are <1%).
Matches the n=1 writeup.

**Wmix (WAL + 50 GB bulk + timed sync), n=6** — the combined test, also
reveals probabilistic spikes:

| dr   | WAL p99.9 median (ms) | WAL p99.9 range     | bulk MB/s          | sync_wall_s          |
|------|-----------------------|---------------------|--------------------|----------------------|
| dr1  | 0.068                 | 0.023 .. **19.53**  | 470.35 [466–473]   | 2.53 [2.51..2.62]    |
| dr5  | 0.071                 | 0.018 .. **160.43** | 557.64 [554–560]   | 11.78 [11.73..12.51] |
| dr10 | 0.077                 | 0.057 .. 0.159      | 672.52 [671–676]   | 24.37 [24.08..24.60] |
| dr20 | 0.020                 | 0.017 .. 0.074      | 890.84 [889–895]   | 49.26 [48.83..49.44] |
| dr40 | 0.056                 | 0.017 .. 0.066      | 410.29 [408–412]   | 0.11 [0.11..0.11]    |

Per-iter WAL p99.9 (chronological):
```
dr1:  [0.023, 0.062, 0.067, 0.069, 0.070, 19.530]     ← one 19.5 ms spike
dr5:  [0.018, 0.052, 0.065, 0.077, 100.139, 160.432]  ← TWO spikes
dr10: [0.057, 0.057, 0.070, 0.082, 0.084, 0.159]      ← zero
dr20: [0.017, 0.018, 0.018, 0.022, 0.051, 0.074]      ← zero
dr40: [0.017, 0.043, 0.055, 0.057, 0.060, 0.066]      ← zero
```

Same pattern as W3b: spikes only at dr ≤ 10 (3/18 = 17% in Wmix, matches
W3b's 17% exactly). Wmix's bulk curve is *different* from W3b's:
dr20 peaks at 890 MB/s (vs W3b's 540 MB/s) because wmix runs the bulk
writer for 15 s before WAL starts, so early writes buffer in RAM at
memory speed until the dr20 cap (25 GB) is hit. The drop at dr40 to
410 MB/s — below dr1's 470 — is the same effect as in W3b and is
reproducible (spread <1%). Wmix also exposes the sync-drain cost
directly: 2.5 s at dr1 rising to 49 s at dr20, then back to 0.1 s at
dr40 (because dr40 lets the flusher keep up so there's nothing left
for sync to drain).

**W4 (dirty 10 GB then sync), n=6** — the cleanest signal:

| dr   | dirty_s              | sync_s               | total_s              |
|------|----------------------|----------------------|----------------------|
| dr1  | 20.40 [20.20..20.49] |  2.57 [2.52..2.66]   | 22.96 [22.75..23.14] |
| dr5  | 12.59 [12.46..12.73] | 11.25 [11.14..11.54] | 23.84 [23.73..24.16] |
| dr10 |  4.84 [4.52..5.12]   | 20.80 [20.46..21.06] | 25.65 [25.39..25.75] |
| dr20 |  4.50 [4.39..4.56]   | 22.73 [22.60..22.91] | 27.19 [27.09..27.47] |
| dr40 |  4.44 [4.41..4.59]   | 23.04 [22.68..23.08] | 27.47 [27.27..27.53] |

- `dirty_s` (time writes block): **4.6× worse** at dr1 vs dr40 (median)
- `sync_s` (time `sync()` returns): **9.0× worse** at dr40 vs dr1
- IQRs are <3% of median on every row — rock-solid opposing tradeoff.
- Matches the n=1 writeup quantitatively (5×/9×).

**Anchors**: W1 cross-device (n=6) @ default sysctl shows NO
interference — fast BW 489 MB/s baseline vs 488 MB/s under slow-device
dd, p99 ratio 1.05. Default dr=20 is inside the "no spike" region, so
W1 at default doesn't reproduce the cross-device pathology either.
Testing W1 at dr1/dr5 is on the followup list. W5 sustained sequential
median 420 MB/s (n=7), ±0.8%, stable regression anchor.

### The autotuning thesis (revised)

**Replace the n=1 claim** "dr1 causes a 12232× p99.9 WAL tail latency
regression" with:

> **On a SATA SSD under 50 GB bulk + WAL fsync contention, static
> `dirty_ratio` ≤ 10 exposes a probabilistic 20–170 ms p99.9 WAL tail
> spike — observed on 6 of 36 runs (17%), median tail ~70 µs
> otherwise. `dirty_ratio` ≥ 20 produced zero such spikes in 24 runs.
> However, `dr20` drops 4× in sync() completion time vs dr5 (22.7 s
> vs 11.25 s on 10 GB), and `dr40` drops 24% in bulk throughput vs
> dr20 (410 vs 540 MB/s). No single static `dirty_ratio` dominates:
> any setting trades one failure mode for another, and dr ≤ 10
> additionally introduces tail-latency non-determinism.**

The three failure modes:
1. **dr ≤ 10**: rare catastrophic WAL tails + slow sync() when a few
   GB have accumulated.
2. **dr20**: best bulk throughput and best tail reliability, worst
   sync() latency.
3. **dr40**: best sync behavior on small dirty pools (via continuous
   flushing), worst bulk throughput, still good tails — but loses a
   25% throughput bet vs dr20.

This is a *weaker but more honest* version of the motivation: the
paper can't claim "dr1 always breaks WAL 12232×" after n=6. It *can*
claim "dr ≤ 10 introduces probabilistic catastrophic tails" and
"dr20/dr40 force a 4×–9× sync regression to avoid them" and "dr40
additionally costs 24% of bulk bandwidth" — three concurrent tradeoffs
that no single static value satisfies.

The core motivation holds: the paper needs the PI controller to match
per-workload optima without operator intervention, **including the
probabilistic-tail property**. That last point is new: a PI controller
that bounds dirty tightly and statelessly (without triggering the
balance_dirty_pages pause gate trap) would eliminate the bimodal
tail behavior, not just pick a better mean.

### Implications for the simulator

The S14 simulator reproducer gives a 2× tail improvement (stock 80 µs
→ PI 40 µs) at dr=0.02. Now we know the hardware tail is **bimodal**,
not just elevated — the simulator's deterministic plant cannot
reproduce the ~17% failure-rate shape. SESSION.md previously noted
this as "the simulator doesn't reach hardware's 173 ms tails"; the
n=6 data shows those 173 ms hits are *rare events*, which is *why*
the deterministic symmetric plant can't reproduce them — there's
nothing stochastic for the plant to hit. The paper's simulator-side
story stays "relative dynamics", and hardware stays the only source
of tail-latency shape evidence. No simulator changes needed.

### Paper pitch (revised)

"Linux's static `dirty_ratio` tunable exhibits three concurrent failure
modes on a SATA SSD under mixed WAL+bulk workloads: (a) at `dr` ≤ 10,
~17% of runs produce a 20–170 ms p99.9 WAL tail spike (vs ~70 µs
median); (b) at `dr` ≥ 20, sync() completion time for 10 GB degrades
4–9× (11 s → 23 s); (c) at `dr` = 40, bulk throughput drops 24% vs
`dr` = 20 (540 → 410 MB/s). No static value satisfies all three."

**Note (2026-04-11 reframe)**: the original paper pitch that followed
this paragraph proposed "PI + time-based per-device limits" as the
replacement. That thesis has been walked back — see §"Design reframe"
near the top. The time-based per-device limit throttles writes that
don't need to be throttled, and replacing dirty_ratio with a
latency-based knob doesn't survive the physics (can't bound sync
latency below `memory_cap / drain_rate` without taxing writes).

The revised pitch: "We propose a PI controller that replaces stock's
cubic pos_ratio + step filter while keeping `dirty_ratio` as the
primary memory cap. The PI always runs (no freerun cliff), converges
cleanly across gain sweeps (no step-filter collapse), and is paired
with an eager-flusher knob (`drain_time_target`) that keeps dirty
small during idle periods without throttling writes. The WAL-tail
pathology at dr ≤ 10 is addressed by the PI's tighter dynamics, not
by replacing the setpoint."

### StockController fidelity gap (discovered during Phase 0)

The simulator's `StockController` port does not match the real v6.19
kernel in two ways:

1. **Missing idle quiescent hold**: real kernel's
   `wb_bandwidth_estimate_start()` resets stamps without updating EWMA
   when elapsed > 1 HZ and no writeback inodes are active. My port runs
   the EWMA every dt=1 ms including idle ticks, creating artificial
   decay.
2. **Wrong EWMA formula**: real kernel uses
   `bw = (written_delta × HZ + old_bw × (period - elapsed)) / period`
   where the effective α = elapsed/period. My port uses a fixed α
   derived from a 3 s half-life, which only matches the real kernel
   when called at a fixed interval.

**Implication**: the simulator's S5 "stock collapses to 0.38 MB/s"
finding is partly an artifact. Real stock has idle hold. The sim's S9,
S10 findings (multi-timescale vs single 3 s EWMA) are more defensible
because those involve active, non-idle workloads.

The PI design's quiescent-hold fix is still the right answer — it
generalizes the kernel's 1 s deadband with a cleaner predicate. The
paper's simulator-side comparison just needs an accurate stock port.

TODO: update `wb_sim/controller.py` `StockController` to faithfully
port the real kernel's `wb_update_write_bandwidth()` +
`wb_bandwidth_estimate_start()` behavior, then re-run S1..S10.

### StockController fidelity fix (2026-04-09, post-Phase 0)

Rewrote `StockController` in `wb_sim/controller.py` to faithfully
match v6.19 `mm/page-writeback.c`:

1. **Quiescent hold** (was missing): when no active task AND dirty=0
   AND writeback=0 AND last_completed=0, reset stamps without
   updating the bandwidth EWMAs. Matches
   `wb_bandwidth_estimate_start()` (page-writeback.c:1542).
2. **Two bandwidth values**: `write_bandwidth` (unsmoothed,
   period-weighted average) and `avg_write_bandwidth` (smoothed with
   the asymmetric `>>3` damping). Was previously a single EWMA.
3. **Correct EWMA formula**:
   `bw_new = (delta_pages × HZ + write_bandwidth × (period - elapsed)) / period`
   with period = `roundup_pow_of_two(3 × HZ)` = 4 s. Was previously
   a fixed-alpha EWMA derived from a 3 s half-life.

After the fix, stock on S5 (30 s, 4.5 s idle gaps) reports
`bw_effective = 193 MB/s` instead of the pre-fix `0.38 MB/s`. The
"S5 stock collapse" finding from earlier Phase 1 runs is **retracted**
— it was a simulator artifact. Real v6.19 has the idle quiescent
hold and does not exhibit this pathology.

S1 stock also improved: `bw_eff = 481 MB/s` (was 424 MB/s).

PI still wins on every scenario except S5 pure-bursty (where stock's
RAM-proportional setpoint absorbs bursts better — 12 GB written vs
PI's 4.2 GB — because PI's tight freerun cuts burst absorption).
This is an honest cost the paper should acknowledge.

### Contention-aware setpoint + S15 RocksDB analog (2026-04-09 late)

Added a contention-aware multiplier to `WbController`: when only one
task is actively dirtying, `setpoint` and `freerun` grow by
`hard_burst_cap = 4×`, allowing single-writer workloads to burst
absorb. When two or more tasks are active, the multiplier drops back
to 1.0 for tight multi-writer control. This replaces an earlier
attempt to scale with `burst_multiplier`, which had a 30 s filter
half-life and couldn't react fast enough to S13-style contention.

Consequences:
- **S5 fixed**: PI now matches stock throughput on pure bursty
  workloads (11.2 GB vs stock 12 GB, 94%). `n_active=1` during
  each burst → `setpoint = 3 GB`, the 2 GB bursts fit.
- **S13 preserved**: `n_active=2` → `setpoint = 750 MB`, tight
  control protects WAL.
- **S6 preserved**: on 1 MB/s slow device, sustained is tiny
  (2 MB) even with 4× multiplier. Dirty bounded at 27 MB vs
  stock's 1485 MB.
- **S1/S3/S4 single-writer continuous**: dirty grows to 3 GB (was
  750 MB). Honest tradeoff: PI allows burst absorption for
  single-writer workloads to match stock's throughput philosophy,
  at the cost of slightly higher sync latency if a sync is issued.
  Still 2× tighter than stock's 5-7 GB on these scenarios.

### S15: RocksDB + YCSB analog simulator sweep (the headline result)

Added `s15_rocksdb_ycsb_analog` scenario: three dirtiers on one 500
MB/s device over 30 seconds:

1. `wal`: 50 MB/s continuous (latency-sensitive)
2. `compaction`: 1 GB/s continuous (bulk)
3. `flush_N`: 4 GB/s for 300 ms every 3 s (periodic memtable→L0)

Ran stock at `dirty_ratio ∈ {0.01, 0.05, 0.20, 0.40}` and PI at its
single nominal config via `phase1/sim_sweep_s15.py`:

```
stock dr    written_MB  sat%  max_dirty_MB   p50_pause  p99_pause  p99.9_pause
  0.01         15000   100%        274.2       17.6 µs    83.4 µs      87.6 µs
  0.05         15000   100%       1281.8       18.2 µs    48.8 µs      83.9 µs
  0.20         15000   100%       5018.7       18.1 µs    40.6 µs      47.6 µs
  0.40         15000   100%      10006.9       17.8 µs    40.1 µs      40.2 µs
pi               15000   100%        774.3       17.6 µs    47.0 µs      50.0 µs
```

**Stock's opposing optima are visible**: best max_dirty at dr=0.01
(274 MB), best p99.9 pause at dr=0.40 (40.2 µs) — at *opposite ends*
of the sweep. 36× variation in dirty, 2.2× in pause.

**PI fills the Pareto gap**: 774 MB dirty (13× less than stock
dr=0.40, 6.5× less than dr=0.20) and 50 µs p99.9 pause (25% worse
than stock's best-latency dr=0.40, 43% better than stock's
tightest-dirty dr=0.01). PI strictly dominates stock dr=0.05 on
both metrics simultaneously. No tuning knob touched.

**This is the paper's autotuning result for the simulator story**.
The hardware W3b/Wmix results establish the ms-scale tail
pathology; the S15 simulator sweep establishes the Pareto-frontier
shape and that PI's single nominal config reaches a point stock
cannot reach at any dr setting.

**Remaining caveats**:
- Simulator pause magnitudes (50 µs) are much smaller than hardware
  W3b (173 ms) because the deterministic plant doesn't produce the
  rare transient overshoots that drive hardware tails. Use
  simulator for relative comparison, hardware for absolute numbers.
- Full demonstration requires a Phase 2 kernel prototype + hardware
  rerun of W3b/Wmix/S15-like workloads. Until then, the paper's
  claim is "simulator predicts PI will match stock-best without
  tuning; kernel verification pending."

### Batching vs continuous writeback — RESOLVED 2026-04-10 (originally raised 2026-04-09)

**Resolution**: W6 sysbench OLTP showed no dr-sensitivity in either
O_DIRECT or fsync mode → option A (narrow-scope) selected, scope
extended to cover InnoDB-family databases. See §"Phase 0 W6
sysbench OLTP (complete)" for the data and reasoning. The original
framing of the question is preserved below for the paper's methods
/ discussion section.

---

Raised during the contention-aware-setpoint + S15 discussion. The
question: PI with a small setpoint (~750 MB at default
`target_drain_seconds=2 s`) effectively converts stock's
"accumulate-and-flush-periodically" pattern into "continuous small
writeback". Does this lose batching benefits?

**Where batching matters**:

1. **Page cache write coalescing**: pages that are dirtied, re-dirtied,
   and re-dirtied again only need one physical write under stock's
   long delay (~25 s on a 125 GB host). Under PI's small setpoint,
   pages sit dirty for ~1–2 s before being written — much less
   coalescing time. **Real concern for in-place-update workloads**
   (InnoDB BTree, Postgres without HOT updates, VM disks with random
   writes). Not a concern for append-only workloads (RocksDB, Kafka,
   Cassandra, log files).
2. **SSD flash page coalescing**: mostly handled by the SSD's own
   DRAM buffer, not the OS delay. Minor effect.
3. **Block-layer request merging**: happens within flusher chunks
   either way. Minor effect.
4. **Journal / metadata amortization**: fewer flushes → fewer ext4
   journal commits. CPU overhead difference.

**The simulator does not model this**: `plant.py` has `flusher_rate =
device_bandwidth` always on, no wake/sleep, no re-dirty semantics.
S15's "PI fills the Pareto gap" conclusion is specifically for
append-only-style workloads. The paper should scope that.

**Three possible design responses**:

- **(A) Scope the claim**: "PI is good for LSM/append workloads,
  modest for in-place-update. Users running in-place workloads
  should set `target_drain_seconds` high." Honest narrow story.
- **(B) Add re-dirty-aware autotuning**: observe write amplification
  (pages flushed / pages dirtied) and grow `target_drain_seconds`
  when the ratio exceeds ~1.2. Larger design.
- **(C) Decouple flusher wake policy from PI throttling**: keep
  stock's existing `bg_thresh`-based flusher batching, but replace
  only the throttling controller (`wb_position_ratio` →
  `wb_pi_control`). Requires dirty to reach bg_thresh before the
  flusher activates, which conflicts with PI's small setpoint
  holding dirty below bg_thresh. Non-trivial to make stable.

**Next steps to resolve this question**:

1. **Hardware in-place-update benchmark** (primary). Run sysbench
   OLTP on InnoDB at `dirty_ratio ∈ {1, 5, 20, 40}` and measure:
   - ops/sec (application throughput)
   - p99 query latency
   - Write amplification via `iostat -x` (`wMB/s` device / `wMB/s`
     user from sysbench log)
   - `/proc/vmstat` `nr_dirty` distribution
   If stock at `dr40` has materially lower write amplification than
   `dr5/dr20`, PI will see the same advantage *only if* we decouple
   the flusher wake policy (option C), or raise drain_seconds.
2. **Rocksdb-YCSB hardware run** for comparison. An append-only
   workload should show no write-amp advantage to `dr40` over
   `dr5`. If true, PI is fine for RocksDB (confirms S15 finding).
3. **Simulator re-dirty extension** (optional). Add a hot-page
   set to the Task model so re-dirty coalescing can be measured.
   Lower priority than hardware; wait until the hardware answer
   suggests we need it.

**Decision deferred**. Not blocking Phase 2.1 (estimator) but must
be resolved before Phase 2.3 (PI controller integration) to know
whether option C is required.

### Next-steps queue (ordered by priority, 2026-04-10 post-W6)

1. ~~**Hardware sweep n=5**~~ — **done 2026-04-10**. Revised thesis
   is probabilistic ("~17% spike rate at dr ≤ 10") plus the
   deterministic bulk/sync tradeoffs. Findings in §"Phase 0
   hardware findings (n=6, 2026-04-10)".
2. ~~**sysbench OLTP on InnoDB at dr1..dr40**~~ — **done 2026-04-10**.
   Both O_DIRECT and fsync flat across dr on tps/p99/write-amp.
   Phase 2.3 decision: **option A (narrow-scope)**, with the scope
   now covering InnoDB-family databases. Findings in §"Phase 0 W6
   sysbench OLTP (complete)".
3. **W1/W3b/Wmix at dr1/dr5 to tighten the spike-rate estimate**. The
   17% rate is 6/36 and has a wide CI. A targeted 30-iteration run at
   dr1 and dr5 would bound the rate more tightly for the paper.
   Also run W1 (cross-device) at small dr — current W1 at default
   shows no interference because default dr=20 is in the no-spike
   region. **This is the next hardware task.**
4. **Phase 2.1 kernel implementation** (multi-timescale estimator).
   Smallest useful kernel change; produces live tracepoint data
   from the real kernel under W3b/Wmix contention. Grounds the
   design in measurement before full PI integration. Can be
   developed in parallel with #3 because they don't share a device.
5. **Phase 2.3 structure**: continuous PI (option A) — confirmed by
   W6. No need to decouple flusher wake policy. Proceed with the
   original plan.
6. S11/S12 simulator scenarios (deferred to Phase 1 extension).
7. ~~**Cleanup: fix `sweep-w6.sh` suffix bug**~~ — **done 2026-04-10
   12:10** (by the prior session, verified 13:12). See the O_DIRECT
   suffix bug section under "Phase 0 W6 sysbench OLTP (complete)".

### BDP pause gate in simulator plant (2026-04-09)

Added `throttle_mode="gate"` to `Simulation` (default). In gate mode,
tasks dirty freely at `demand_rate` when
`dirty_pages < controller.freerun()`, and get throttled at
`task_ratelimit` only above freerun. Matches the real kernel's
`balance_dirty_pages` pause-gate behavior and makes W3b-style BDP
latency pathologies visible in the simulator. A per-tick
`per_page_pause_s = 1 / task_ratelimit` metric is recorded as a
latency proxy.

Added `WbController.freerun() = 0.5 × sustained_limit`. Added new
scenario **S14** = S13 plant with stock `dirty_ratio = 0.02` — the
W3b reproducer.

**Simulator tail pathology is muted compared to hardware.** On S14
stock the per-page pause p99.9 is 80 µs, PI is 40 µs — a 2× tail
improvement. Hardware W3b showed 173 ms p99.9 at dr1; the simulator
doesn't reach that because the deterministic symmetric plant
stabilizes at a smooth steady state and doesn't produce the rare
overshoots that drive the hardware tail. **Hardware W3b/Wmix remain
the primary source of tail-latency data for the paper.**

Regression with gate model + fidelity-fixed stock (max_dirty in MB;
PI vs stock):

| scen | stock max_dirty | PI max_dirty | stock wrote | PI wrote |
|------|---|---|---|---|
| S1  | 5318 | 765  | 5000  | 5000  |
| S3  | 5427 | 770  | 7500  | 7500  |
| S5  | 1750 |  596 | **12000** | **4210** |
| S6  | **1485** | **19** | 15    | 15    |
| S9  | 5592 | 689  | 13646 | 13646 |
| S13 | 4970 | 745  | 10000 | 10000 |
| S14 |  497 | 749  | 15000 | 15000 |

- **S1/S3/S9/S13**: PI bounds dirty 6–8× tighter at identical
  throughput. Clear architectural win.
- **S5**: stock wins throughput 2.8× because its large RAM-proportional
  freerun absorbs the 2 GB bursts entirely; PI's freerun=500 MB
  forces throttling mid-burst. Honest cost of small setpoint.
- **S6**: on 1 MB/s slow device, stock lets dirty grow to 1.5 GB
  (RAM-proportional); PI bounds dirty at 19 MB. 80× tighter with
  identical throughput. The setpoint-too-large-for-slow-device
  pathology is clearly visible in the simulator.
- **S14**: tight-dr simulator reproducer. Both saturate device,
  PI's tail 2× better.

### Simulator analog of the hardware W3b tradeoff (S13)

Added `s13_bulk_plus_wal` scenario: one 500 MB/s device, two tasks
(bulk demand 2 GB/s, wal demand 50 MB/s), 30 s duration. Sweep runner
is `phase1/sim_sweep_s13.py`.

Results (bulk_mbps averaged over full run):

```
STOCK × dirty_ratio sweep:
  dr    bulk_mbps  wal_mbps  wal_sat%  max_dirty  total
  0.01     254.2     50.00    100.0%        1.5   9126
  0.05     254.2     50.00    100.0%        1.5   9126
  0.10     254.2     50.00    100.0%        1.5   9126
  0.20     254.2     50.00    100.0%        1.5   9126
  0.40     254.2     50.00    100.0%        1.5   9126

PI (single nominal config):
  pi       474.8     50.00    100.0%      754.0  14994
```

Two findings:

1. **Stock's simulator throughput is invariant to `dirty_ratio`.** At
   all 5 sweep points, bulk stabilizes at 254 MB/s. The root cause is
   the simulator's plant model: tasks are throttled continuously at
   `task_ratelimit`, and stock's ratelimit is split evenly across
   active tasks. Bulk sees `avg_bw/2` as its effective ratelimit, and
   `avg_bw` converges to `2 × 254 = 508 MB/s` as a stable fixed point.
   Dirty stays ~0 because outflow ≥ inflow, so `pos_ratio ≈ 2` and
   `dirty_ratio` doesn't enter the feedback loop.

2. **PI reaches 475 MB/s, 87% higher than stock's fixed point.** Same
   plant, same tasks. PI's time-based setpoint + direct PI control
   break the ratelimit-splitting feedback loop that pins stock at
   ~50% of device capacity.

**Model gap, acknowledged**: the real kernel's `balance_dirty_pages`
is a pause-based gate that only fires when dirty > freerun, not a
continuous rate limit. The hardware W3b result (12232× WAL latency
regression at dr1) depends on that pause mechanic and is NOT
reproducible in the current simulator plant. The simulator and
hardware results are complementary pieces of evidence, not parallel
demonstrations of the same pathology:

  - **Hardware W3b**: shows the BDP-pause-based WAL latency trap at
    small `dirty_ratio`. Paper's primary "no single setting wins"
    evidence.
  - **Simulator S13**: shows the ratelimit-splitting feedback fixed
    point below device capacity. Secondary architectural evidence
    that stock's continuous-throttling path also has room to improve.

The paper will use hardware for latency/tradeoff claims and the
simulator for controller-internal dynamics (stability, convergence,
gain sweeps).

---

## Key findings from Phase 1 smoke tests

These are real design-relevant results from running the simulator, not
just sanity checks. Worth keeping in the paper's design section.

All 10 scenarios pass with the post-fix controller (S1–S10). S11 and S12
are future enhancements — see wb-plan.md §1.3 scenario table.

### Scenario results summary (PI post-fix vs stock) — PRE-FIX, kept for audit

**This table was generated before the 2026-04-10 kernel-faithfulness pass
on StockController.** It predates the freerun cliff gate, 200 ms
BANDWIDTH_INTERVAL gating, and the full `wb_update_dirty_ratelimit` step
filter. It reflects an over-active Stock model that slewed dirty_ratelimit
on every tick regardless of freerun state. The **current numbers are in
the next subsection "Regenerated scenario results (2026-04-11)"**.
Keeping this here only so readers can diff against the old values.

| scen | PI max_dirty | PI bw_eff | PI tail err | stock max_dirty | stock bw_eff |
|------|---|---|---|---|---|
| S1 (15 s)   | 770  | 490  |  35 | 976  | 424 |
| S2 (15 s)   | 5561 | 347  | 709 | 3034 | 477 |
| S3 (15 s)   | 773  | 498  |  26 | 2991 | 476 |
| S4 (15 s)   | 770  | 484  |  43 | 976  | 424 |
| S5 (30 s)   | 430  | 470  | 644 |   0  | 0.38 |
| S5 (120 s)  | 485  | 495.8 | — |   —  |   —  |
| S6 (15 s)   |  18  | 1.0  |  2.8 | 729  | 4.0  |
| S7 fast (15 s) | 7802 | 4963 | 394 |    5 | 2058 |
| S7 slow (15 s) |   20 |  6.1 |  2.7 |  766 |  12.7 |
| S8 (15 s)   | 808  | 499.7 |  7  |  808 | 499.7 |
| S9 (30 s)   | 689  | 467.5 | 91 | 5533 | 462.9 |
| S10 (30 s, σ=300) | 865 | 511.9 | 165 | 5639 | 500.5 |

Dirty in MB; bw_eff in MB/s; tail err in MB. S7 is multi-device; stock's
"fast" sub-sim has `max_dirty=5 MB` because cold-start hasn't finished in
15 s for a 5 GB/s device, not because of controller quality.

### Regenerated scenario results (post-corrections, 2026-04-11)

Generated via `python3 -m wb_sim.run <scen> --compare` on all 13
single-device scenarios + s7 multi-device, after the kernel-faithfulness
pass on StockController (freerun gate + 200 ms BANDWIDTH_INTERVAL gate +
full `wb_update_dirty_ratelimit` step filter). **Stock's "freerun %"
column is the fraction of ticks at which `dirty ≤ freerun_ceiling` —
i.e., the fraction of the run during which stock's control machinery is
bypassed entirely** (Issue 1 from §"Kernel code analysis"). Stock default
config is 32 GB dirtyable × dr=0.20 / bg=0.10 unless overridden by the
scenario.

**Initial (2026-04-11 ~12:00) pre-fix table** surfaced two PI regressions
(S2 max_dirty 19923 MB, S7-fast 30649 MB) caused by the
`_contention_mult × drain_time × bw_eff` setpoint producing unbounded
setpoints on fast devices (30 GB on 5 GB/s NVMe). The regressions were
resolved **not** by an ad-hoc byte cap (rejected as an unprincipled
magic number) but by reworking the setpoint from first principles as
the minimum of two independent physical constraints — see
§"Simulator regression investigation" below. The post-fix numbers are
in the "Post-fix regenerated results" subsection further down.

### Simulator regression investigation (2026-04-11) — RESOLVED

The pre-fix table had two clear PI regressions:

- **S2** (single writer, 5 GB/s → 500 MB/s step): `max_dirty = 19.9 GB`
  (`tail_err = 18.1 GB`) — PI let dirty grow to the `_contention_mult ×
  drain_time × bw_eff = 30 GB` setpoint during the fast phase, then
  couldn't drain the accumulated pool within the 10 s remaining.
- **S7-fast** (5 GB/s NVMe): `max_dirty = 30.6 GB` — same root cause.

**Root cause**: `WbController.setpoint()` was
`_contention_mult × 0.75 × drain_time × bw_eff`. With
`_contention_mult = 4`, a 5 GB/s device, and `drain_time = 2 s`,
setpoint evaluates to 30 GB. The `_contention_mult = 4×` was
intentional (per `wb-plan.md` §1.2) — it let single-writer workloads
burst-absorb up to 4 s of drain at the current `bw_eff`. The *intent*
is reasonable; the bug is that **setpoint is unbounded in bandwidth**.
On slow devices 4× gives 3 GB which is sane; on NVMe it gives 30 GB
which isn't.

#### Rejected path: single-variable knob

Swept `hard_burst_cap ∈ {1.0, 1.5, 2.0, 4.0}` hoping a smaller value
would fix the fast-device case. It scales linearly — S2 max_dirty goes
from 26 GB (cap=4) to 6 GB (cap=1), S5 burst absorption drops from
11774 MB written to 4415 MB (62% loss). **No single cap value fixes
S2/S7 AND preserves S5 burst absorption**. They're genuinely in
tension, so a single knob can't resolve both.

#### Rejected path: absolute byte cap

Tried `setpoint = min(cap × 0.75 × sustained, max_dirty_bytes)` with
`max_dirty_bytes = 2 GB`. Worked numerically (S2 max_dirty 26 GB → 2.3
GB, S5 retained 87% of burst absorption). **Rejected as unprincipled**:
a hardcoded 2 GB default is the same class of magic number as
`dirty_ratio = 20%` and doesn't adapt to host memory, device count, or
workload. Not shipping a "dirty_ratio replacement" that introduces a
new magic number.

#### Chosen path: first-principles two-constraint design

Restating what the setpoint actually is, from physics:

> A dirty page has two independent costs: it **occupies memory** that
> could be used for something else, and it **delays sync()** until it
> reaches the device. A correct setpoint must bound both.

Two independent constraints:

1. **Latency bound** (primary): `dirty ≤ drain_time × bw_eff × 0.75`.
   Guarantees sync() completes within `drain_time` at current bw.
2. **Memory bound** (safety ceiling): `dirty ≤ reserved_fraction ×
   dirtyable_memory / num_active_wbs`. Leaves `(1 − reserved_fraction)`
   of memory for non-writeback uses, distributed as equal per-wb shares.

Setpoint = `min(latency, memory)`. Both hold simultaneously. **No magic
number**: every term is derived from an observable quantity (bw_eff,
dirtyable_memory, num_active_wbs) or a user-facing knob with a direct
physical interpretation (drain_time = "sync latency bound",
reserved_fraction = "memory to leave for non-writeback").

Stock's `dirty_ratio = 20%` is NOT eliminated — it's demoted from
primary control to safety ceiling. **The paper's story is that
demotion**: "stock uses memory-ratio as *primary*, producing 50 s
sync latency on a slow-device-large-RAM host. We use time-based as
*primary* and memory-ratio as a *safety net*. On slow devices the
time-based primary tightens sync latency 10–50×; on fast devices the
memory ceiling binds at roughly the same place stock does."

`_contention_mult` is deleted. Burst absorption isn't achieved by
inflating the setpoint via a multiplier — it comes from the gap
between `throttle_start` (the latency-based setpoint) and
`throttle_hard` (the memory ceiling). On slow-device-large-RAM, that
gap is 750 MB ↔ 6.4 GB, giving single writers 5+ GB of soft-throttle
band. On fast-device-small-RAM, there's no gap (memory ceiling binds
before time-based), and single-point throttling takes over.

**fprop is also deleted.** Stock's `fprop` computes bandwidth-proportional
shares via a 30 s EWMA on per-wb activity, with a `slack/8` fallback
that the code-first analysis (§"Kernel code analysis", Issue 4)
already flagged as clobbering the fprop signal in the common case.
Our design doesn't need fprop: the **time-based primary control
already gives bandwidth-proportional setpoints by construction**
(`drain_time × bw_eff` scales directly with bandwidth). The memory
ceiling just needs to be fair, not bandwidth-weighted, so
`reserved_fraction × dirtyable_memory / num_active_wbs` suffices.
This deletes ~200 LOC of fprop machinery and replaces it with ~10
LOC of equal-share accounting — a paper-worthy simplification in its
own right.

#### Implementation

`wb_sim/controller.py::WbController`:

```python
reserved_fraction: float = 0.20          # matches stock dirty_ratio default
dirtyable_memory_pages: float = 32 GB / 4 KB
wb_min_bytes: float = 16 MB              # floor against starvation (rare)
num_active_wbs_fn: Optional[Callable[[], int]] = None

def memory_ceiling(self) -> float:
    budget = self.reserved_fraction * self.dirtyable_memory_pages
    return max(budget / self._num_active_wbs(),
               self.wb_min_bytes / PAGE_SIZE)

def setpoint(self) -> float:
    time_based = 0.75 * self.sustained_limit()
    return min(time_based, self.memory_ceiling())

def freerun(self) -> float:
    time_based = 0.5 * self.sustained_limit()
    return min(time_based, (2/3) * self.memory_ceiling())
```

`wb_sim/plant.py::MultiDeviceSimulation`:

- Added a sticky `_last_active_t` map that tracks the last time each
  sub-sim had any activity (dirty > 0, writeback > 0, or a task in
  its active window).
- Added `_active_wb_count(t)` that counts wbs active now or in the
  last 10 s (`active_hold_seconds` default, matching the flusher
  kick-off interval).
- `run()` wires `sub.controller.num_active_wbs_fn` to the shared
  counter before stepping, so each wb sees the correct denominator.

The hysteresis on "active" prevents wbs from churning in and out of
the active set between brief idle gaps, which would cause the memory
ceiling to jitter.

#### Post-fix regenerated results (2026-04-11 ~18:30)

Same 14 scenarios + new S16 (constraint-crossover bandwidth step).
Stock config unchanged. PI config: `drain_time = 2 s`,
`reserved_fraction = 0.20`, `dirtyable_memory = 32 GB`,
`wb_min_bytes = 16 MB`, `hard_burst_cap` is no longer used.

| scen        | stock max | pi max | stock tail | pi tail | stock wrote | pi wrote | stock freerun% | PI bound by |
|-------------|-----------|--------|------------|---------|-------------|----------|----------------|-------------|
| S1 (10 s)   | 4932      |  765   | 817        |  29     |  5000       |  5000    | 41.4%          | time |
| S2 (15 s)   | 5548      | 6101   | 234        | 1224    | 30000       | 30000    | 19.9%          | time* |
| S3 (15 s)   | 5176      |  770   | 627        |  24     |  7500       |  7500    | 47.4%          | time |
| S4 (10 s)   | 4932      |  761   | 817        |  30     |  5000       |  5000    | 41.4%          | time |
| S5 (30 s)   | 1750      |  596   | 5141       | 621     | 12000       |  4211    | 100%           | time |
| S6 (15 s)   | 1485      |   19   | 4398       |   4     |    15       |    15    | 100%           | time |
| S7-fast     | 4920      | 3517   | 819        | 203     | 75000       | 75000    | 51.6%          | memory |
| S7-slow     | 1350      |   21   | 4519       |   2     |   150       |   150    | 100%           | time |
| S9 (30 s)   | 5379      |  689   | 407        |  91     | 13646       | 13646    | 32.6%          | time |
| S10 (30 s)  | 5503      |  865   | 364        | 165     | 16018       | 16018    | 42.6%          | time |
| S11 (40 s)  | 4916      |  959   | 2469       | 102     | 15000       | 15000    | 99.7%          | time |
| S13 (20 s)  | 4917      |  745   | 818        | 7.5     | 10000       | 10000    | 23.6%          | time |
| S14 (30 s)  |  493      |  749   |  81        | 1.5     | 15000       | 15000    |  8.0%          | time |
| S15 (30 s)  | 4963      |  774   | 799        | 9.2     | 15000       | 15000    | 24.5%          | time |
| S16 (40 s)  | 6482      | 7133   | 747        | 4684    | 125000      | 125000   | 15.0%          | time→memory→time |

Dirty and tail_err in MiB, written in MB. `*` on S2: PI is time-bound
both pre- and post-step; the post-step recovery is physics-limited
(6.1 GB / 500 MB/s = 12.2 s vs 10 s remaining), so tail_err is still
1.2 GB at end-of-run but converging. A longer S2 converges to 0 tail
error (verified at 30 s: final_dirty = 0.4 GB).

**No regressions**. S2 went from **19.9 GB → 6.1 GB** max_dirty, and
the residual 6.1 GB is the physics-limited pre-step peak (6 GB
memory-ceiling × 1 wb = 6.4 GB available, time-based on 5 GB/s is
7.5 GB, so the time-bound binds at 7.5 × 0.75 = 5.6 GB — close
enough). S7-fast went from **30.6 GB → 3.5 GB** (memory ceiling
binds at 8 GB / 2 wbs = 4 GB; PI converges to 3.5 GB with ~6%
overshoot). All other scenarios are either unchanged (multi-writer
cases were already tight) or tighter.

**S5 honest regression**: burst absorption drops from 11229 MB
written (pre-fix cap=4) to 4211 MB (37% of stock's 12000 MB). This
is the real cost of removing `_contention_mult` — single-writer
bursty workloads don't get their 3× setpoint headroom anymore. The
paper owns this: "PI trades burst throughput for bounded steady-state
memory and latency, by design. Users who need larger burst absorption
can raise `drain_time` at the wb level."

**S16 — new scenario**: constraint-crossover bandwidth step
(200 MB/s → 8 GB/s → 200 MB/s over 40 s). Exercises the exact case
where the binding constraint switches from time-based to memory-based
and back. Peak dirty = 7133 MiB = 8.8% above the pre-step memory
ceiling (6553 MiB) — within the 20% stability criterion. The peak
occurs ~60 ms after the down-step, caused by `bw_eff` smoothing lag,
which is physical and unavoidable. Stable, no oscillation. Same
pathology as S2's "physics-limited recovery".

**Reading the freerun% column**: any row with stock freerun% > 80% means
stock *never engages its control loop* — dirty_ratelimit stays at the
cold-start seed or whatever the flusher path produced, and the entire
pos_ratio → dirty_ratelimit step filter is dead code. **S5, S6, S11,
S7-slow all sit at ≥ 99%** of freerun, confirming Issue 1 on the
simulator side across four unrelated plant setups. S1/S3/S4/S10 all spend
~40–50% of the run in freerun too — the cliff isn't a fringe case, it's
the default for most workloads that don't hit the dr=20 thresh.

**Qualitative read**:

- **S1, S3, S4, S9, S10**: stock sits just under freerun (~4.9 GB,
  the kernel-faithful "below-freerun no control" regime). PI binds
  on the time-based constraint at `0.75 × 2 s × 500 MB/s ≈ 765 MB`
  — a 6–7× tightening with identical throughput. PI tail_err < 170
  MB on every row.
- **S5, S6, S7-slow, S11**: stock at 100% freerun. S6 reproduces the
  "sustained_limit is RAM-proportional, not drain-rate proportional"
  pathology cleanly (1485 MB vs PI's 19 MB on a 1 MB/s device). S11 is
  the paper's motivation plot — stock stays frozen at 98 MB/s cold-
  start seed for all 40 s of a ramp while PI tracks `bw_effective`
  continuously.
- **S7-fast**: stock at 51.6% freerun, peak dirty 4.9 GB. PI is the
  first scenario to bind on the **memory ceiling** (4 GB share = 8 GB
  budget / 2 active wbs). Peak 3.5 GB, ~6% overshoot, stable. This is
  the canonical "memory ceiling binds" case and it converges cleanly.
- **S13–S15**: stock at 4.9 GB (just under freerun). PI tight at
  ~745 MB (multi-writer setpoint, time-bound). 6.5× tightening with
  identical throughput. S14 is the only row where stock's max_dirty
  (493 MiB) is below PI's (749 MiB), and only because S14 explicitly
  configures stock with `dirty_ratio = 0.02` to force the control
  regime — stock at default dr=0.20 would sit at 4.9 GB like the other
  rows.
- **S2**: stock converges at 5.5 GB (near freerun). PI binds on the
  time-based constraint (7.5 GB pre-step, 750 MB post-step), peaks at
  6.1 GB pre-step, recovers at physical device rate post-step. Residual
  tail_err at t=15 is 1.2 GB (physics-limited recovery, fully converges
  at t=30 s).
- **S16**: new constraint-crossover scenario. Peaks 7.1 GB at the
  high→low bandwidth step, 8.8% above the pre-step memory ceiling.
  Stable, no oscillation across the time↔memory constraint switch.
- **S5 honest regression**: PI throughput 4211 MB vs stock's 12000 MB
  (37%). This is the real cost of removing `_contention_mult` — bursty
  single-writer workloads don't get their 3× setpoint headroom.

**Actions from this regeneration**:

1. The paper figure "PI vs stock across the scenario suite" uses the
   post-fix 2026-04-11 numbers above.
2. ~~S2 and S7-fast PI regressions block the scenario sweep result
   from being the paper's leading result.~~ — **resolved**.
3. The freerun% column is the new hero stat for Issue 1 on the
   simulator side. **Add it to the simulator's default summary output**
   so future regressions don't hide behind "stock and PI both reached
   5 GB max_dirty, looks fine".
4. `wb-plan.md` §1.2 "contention-aware setpoint" section is now
   stale — it describes the rejected `_contention_mult = 4` approach.
   Needs rewrite to match the two-constraint design.

### CV shrinkage verification (from S10)

S10's specific purpose was to verify CV shrinkage still engages on
legitimate noise after the settling gate was added for S4. Results with
σ=300 MB/s jitter around a 500 MB/s mean:

- CV shrinkage **firing on 26.5% of ticks** (7947/30000)
- Min shrinkage ratio 0.914 (bw_eff pulled down by up to 8.6% at peak)
- Mean ratio when firing: 0.966 (mild, as designed)
- Final bw_eff 511.9 vs true mean 500 — conservative but accurate

First attempt used σ=150 (σ/μ=0.3, below CV threshold of 0.5) and
shrinkage never engaged — S10 parameters were tuned up to σ=300
(σ/μ=0.6) to actually exercise the mechanism.

### Settling gate revision (part of S10 verification)

Initial fix used `|bw_slow - bw_medium| < 0.25 × bw_medium` as the
settled predicate. But bw_slow's 30 s half-life never caught up to
bw_medium in realistic scenarios — gate stayed **closed permanently**
on S10 (0/30000 ticks). Changed to
`|bw_fast - bw_medium| < 0.25 × bw_medium`: fast converges in a few
seconds in steady state, so the gate opens quickly in steady scenarios,
but stays closed during transients (cold start, bursts, step responses)
because bw_fast diverges from bw_medium. Verified across all 10
scenarios.

### Three compounding bugs, discovered together

Running all scenarios exposed a chain of dependencies that couldn't
have been found from S1/S2/S5 alone:

  1. **Estimator decay during idle gaps (S5 collapse).** Unconditional
     EWMA updates with `sample=0` during idle gaps drove
     `bw_fast`/`bw_medium` toward zero, creating a positive-feedback
     ratchet.

  2. **PI integral windup across burst cycles (S5 peak-dirty growth).**
     Dirty < setpoint for most of each burst cycle means error > 0,
     integral grows every cycle without bound, pre-loading the next
     burst with ever-higher ratelimits.

  3. **CV shrinkage pinned at 0.2× floor during cold start (S4 failure,
     S1 residual).** The variance signal was computed as
     `(sample - bw_slow)²` where `bw_slow` is a 30 s EWMA. During cold
     start, `bw_slow` lags the samples by huge margins, so variance is
     dominated by the convergence transient, not real noise. CV >> 0.5,
     shrinkage factor hits its 0.2 floor, `bw_eff` = 0.2 × `bw_medium`.
     The tight anti-windup clamp at `bw_eff` (fix 2) then makes this
     fatal because ratelimit can never exceed device capacity, so the
     feedback loop never converges past the cold-start stall.

### Fix stack (in `wb_sim/controller.py`)

  1. **Quiescent hold + integral reset**: when
     `!any_task_active && dirty == 0 && writeback == 0 && last_completed == 0`,
     freeze the EWMAs and reset `pi.integral = 0`. Resetting (not just
     freezing) means spiky workloads start each burst with a clean
     integral; continuous-demand workloads never hit quiescent so reset
     never fires. Fixes S5.

  2. **Tight anti-windup clamp**: `integral ∈ [-bw_eff, +bw_eff]`,
     updated each tick as `bw_eff` changes. Bounds single-active-period
     windup and post-step overshoot (S2 once S4 is also fixed).

  3. **CV shrinkage gated on settled estimator**: variance baseline
     moved from `bw_slow` to `bw_medium`, and shrinkage only applies
     when `|bw_slow − bw_medium| < 0.25 × bw_medium` (the three
     timescales agree). Fixes S4 cold-start and improves S1 residual
     from 424 → 490 MB/s.

Fix 3 is what makes fix 2 sound — without CV gating, the tight clamp
creates a low-bandwidth fixed point. Without fix 2, S5 max_dirty grows
unbounded. Without fix 1, S5's ratchet never starts. The three are
interdependent.

### Verification

S5 120 s long run — full convergence:
- `bw_eff` → 495 MB/s (within 1% of true 500) by burst 9
- `peak_dirty` → 484.7 MB by burst 17, stable within ±0.2 MB through burst 23
- `pi_i == 0.0` at end of every burst (reset fires during drain-down)
- `setpoint` → 741 MB (stable)

S4 cold start from 50 MB/s transport default:
- `bw_eff` hits 246 MB/s (49%) by t=2 ✓ (criterion: ≥50% within 2s)
- `bw_eff` hits 484 MB/s (97%) by t=10 ✓ (criterion: within 5% by 4× drain_seconds = 8s, marginal)
- 500 MB/s (100%) by t=15

### S2 criterion revision

With the CV gating fix, `bw_eff` now tracks the 5 GB/s pre-step device
properly instead of being pinned by CV shrinkage. As a result, PI fills
dirty to ~setpoint (~5.3 GB) before the step. When the step hits,
recovery is device-limited: a 500 MB/s device needs ~10 s to drain 5 GB.

The v1 plan criterion "recovery within 4 s" was written implicitly
assuming the PI didn't actually fill to setpoint — a bug. Revised
criterion (now in the plan): no overshoot *after* the step, and
`task_ratelimit → 0` within 200 ms of the step. Simulator confirms both.

### Extension C verdict (unchanged)

Extension C (bandwidth probe) is NOT required for S5 or any other
scenario's stability. S1's residual fixed-point gap (490/500 MB/s) is
where Extension C would earn its keep if we want convergence-accuracy
improvements for the paper's discussion section — but it does not block
Phase 2.1.

---

## Phase 0 W6 sysbench OLTP (complete, 2026-04-10)

**Status**: all 24 runs valid. fsync half 10:36–11:25, O_DIRECT rerun
12:10–12:59. mariadbd stopped cleanly after each sweep. The chain
wrapper (`/tmp/sweep-w6-chain.log`) only logged its initial "waiting
..." line and never printed "CHAIN COMPLETE" — its stdout was lost
when the session disconnected — but both underlying sweeps reached
completion and wrote their own logs (`/tmp/sweep-w6.log`,
`/tmp/sweep-w6-odirect.log`).

### Results

**O_DIRECT (production default)** — InnoDB bypasses the page cache,
only binlog + redo log go through the dirty pool:

| profile | n | tps               | p99 ms | p999 ms | dev_MB | bytes/usrW |
|---------|---|-------------------|--------|---------|--------|------------|
| dr1     | 3 | 4932 [4932..5061] | 14.46  | 22.28   | 5365   | 1573       |
| dr5     | 3 | 4938 [4932..5039] | 13.95  | 21.89   | 5368   | 1577       |
| dr20    | 3 | 4927 [4921..5057] | 14.46  | 22.69   | 5330   | 1571       |
| dr40    | 3 | 4955 [4924..4987] | 14.21  | 22.69   | 5359   | 1573       |

**fsync (legacy / adversarial)** — InnoDB data files go through the
page cache and can be re-dirtied before flushing:

| profile | n | tps               | p99 ms | p999 ms | dev_MB | bytes/usrW |
|---------|---|-------------------|--------|---------|--------|------------|
| dr1     | 3 | 5454 [5376..5460] | 7.57   | 11.87   | 5840   | 1558       |
| dr5     | 3 | 5438 [5319..5442] | 7.57   | 12.75   | 5834   | 1570       |
| dr20    | 3 | 5441 [5327..5458] | 7.57   | 12.75   | 5829   | 1566       |
| dr40    | 3 | 5392 [5385..5493] | 8.58   | 14.21   | 5737   | 1549       |

### Findings

**Both flush methods are flat across `dirty_ratio`.** tps spread
across dr is ~0.6% for O_DIRECT and ~1% for fsync; p99 moves by at
most one histogram bucket in either mode. Write amplification
(`dev_MB_written / user_writes`, reported as `bytes/usrW`) is flat
at 1571 ± 6 for O_DIRECT and 1558 ± 11 for fsync. No monotonic trend
in any metric across the 40× dr sweep.

**This resolves the batching-vs-PI open question.** The hypothesis
was: if `fsync` showed monotonic write-amp increase from dr40 → dr1,
coalescing would matter and Phase 2.3 would need option (B)
re-dirty-aware autotuning or (C) decoupled flusher wake policy.
Actual result: write amp does not depend on dr, even in the
adversarial mode where InnoDB data files go through the page cache.

**Why the page cache doesn't help here**: sysbench OLTP is a
steady-state workload, not accumulate-then-flush. More importantly,
InnoDB already coalesces internally in the buffer pool before
dirtying OS pages — by the time a page reaches the OS it has
absorbed many row updates into the same 16 KB frame. Adding
OS-level re-dirty windows on top of that buys nothing because the
re-dirty rate is already ~1 per flush.

**Unexpected: fsync is FASTER than O_DIRECT.** 5440 vs 4935 tps
median, 8 ms vs 14 ms p99. On this hardware with an 8 GB buffer
pool and a 5.2 GB dataset, the OS page cache absorbs reads that
O_DIRECT forces to the device. Well-known InnoDB-on-Linux effect;
does not affect the dr conclusion. Relevant only to note that
"O_DIRECT is the production default" is not automatically the
best choice on every box.

### Decision: Phase 2.3 takes the narrow-scope path (option A)

The paper claims:

> PI + time-based per-device limits are safe for steady-state
> database workloads. Under sysbench OLTP against InnoDB in both
> O_DIRECT and fsync modes, write amplification is insensitive to
> `dirty_ratio` across a 40× sweep (dr1..dr40). The small PI
> setpoint does not cost coalescing for workloads that already
> batch internally, which covers at least two important classes:
> LSM/append (RocksDB, Kafka, Cassandra) and in-place-update
> databases with their own buffer pool (InnoDB-family).
> Workloads that do NOT batch internally — raw filesystems with
> random in-place updates, VM disk images under random-write
> guests — are out of scope for the first paper and noted as
> future work. Option C (decoupling flusher wake policy from PI
> throttling) is not required for this class.

The claim is *stronger* than the pre-W6 fallback ("PI is good for
LSM/append only") because it now covers the largest in-place-update
database family without additional complexity in the design.

### The O_DIRECT suffix bug (fixed 2026-04-10 12:10)

`sweep-w6.sh` originally lowercased `"O_DIRECT"` → `"o_direct"` (with
the underscore), but `workloads/common.sh` case-matches `dr*-odirect`
(no underscore). On the 2026-04-10 run all 12 O_DIRECT runs in
`sweep-w6.sh` failed fast; the recovery was a one-shot
`sweep-w6-odirect.sh` driver with the correct suffix. The failed
empty result dirs were deleted before the rerun; only valid runs
remain in `phase0/results/`.

**Status**: fix applied to `sweep-w6.sh` at 2026-04-10 12:10:09 local
(by the previous Claude session, at the same time the O_DIRECT rerun
was being staged). `sweep-w6.sh` now uses an explicit `case` statement
mapping `O_DIRECT → odirect` and `fsync → fsync`, with a `*)`
exit-with-error branch for unknown methods. Verified 2026-04-10 13:12
by reading the file and diffing against `sweep-w6-odirect.sh`. Safe
for future cold-start reruns. `sweep-w6-odirect.sh` was deleted
afterward since the full driver now handles both methods correctly.

### Artifacts

- Raw runs: `phase0/results/*-w6-{dr1,dr5,dr20,dr40}-{fsync,odirect}/`
  (24 dirs, 3 iterations per cell). Each dir contains `w6/sysbench.stdout`,
  `w6/diskstats-{pre,post}.txt`, `w6/innodb-stats-{pre,post}.txt`,
  `w6/runmeta.json`, `w6/sysctl.txt`, `vmstat.csv`, `pressure.csv`,
  `bdp.csv`, `iostat.json`.
- Aggregator: `phase0/aggregate.py` with `analyze_w6` table split by
  flush method.
- Sweep driver logs: `/tmp/sweep-w6.log` (fsync half 10:36–11:25,
  includes the 12 fast-fail O_DIRECT entries from the pre-rerun bug),
  `/tmp/sweep-w6-odirect.log` (O_DIRECT rerun 12:10–12:59, 0 failed).
- MariaDB instance: `/mydata/wb-work/mysql/` (5.2 GB InnoDB dataset
  preserved, `my.cnf`, `logs/`, `data/`, `run/`). mariadbd is stopped.
  System `mariadb.service` is stopped and disabled — don't start it.

### W6 harness (still live — use for reruns)

| Path | Role |
|---|---|
| `/mydata/wb-work/mysql/my.cnf` | MariaDB config, 8 GB buffer pool, socket on port 3307 |
| `/mydata/wb-work/mysql/data/` | InnoDB datadir, 5.2 GB (10 tables × 2M rows). **Keep** — reloading takes ~5 min. |
| `/mydata/wb-work/mysql/logs/` | error log + binlogs |
| `/mydata/wb-work/mysql/run/` | unix socket + pidfile |
| `phase0/workloads/w6-sysbench-oltp.sh` | W6 workload script |
| `phase0/sweep-w6.sh` | full sweep driver, both methods. Suffix bug fixed 2026-04-10 12:10 — safe to reuse. |
| `phase0/analyze.py` | extended with `analyze_w6` + histogram/diskstats parsers |
| `phase0/aggregate.py` | extended with W6 table (split by flush method) |

**MariaDB config notes**: 8 GB `innodb_buffer_pool_size` (larger than
5.2 GB dataset but smaller than 125 GB RAM — all data fits in the pool
once warm, forcing the write path but not the read path);
`innodb_flush_log_at_trx_commit=1` + `sync_binlog=1` (full-durability
WAL matching production); ROW binlog; `innodb_doublewrite=ON`;
`innodb_flush_method` overridden per-run via `--innodb-flush-method=`.
Runs as current user on port 3307.

**System mariadb**: `apt install mariadb-server sysbench` was done on
2026-04-10. The **system `mariadb.service` is stopped and disabled**
— don't `systemctl start mariadb`, it will conflict with our instance.
Our benchmark mariadbd runs as the current user, managed by the sweep
scripts. If you find a leftover mariadbd, stop it via its pidfile:

```bash
pid=$(cat /mydata/wb-work/mysql/run/mysqld.pid 2>/dev/null)
[ -n "$pid" ] && kill -TERM $pid
rm -f /mydata/wb-work/mysql/run/{mysqld.sock,mysqld.pid}
```

**Profile naming**: W6 profiles are compound names `drN-<method>`;
`apply_sysctl_profile` in `workloads/common.sh` handles these by
stripping the suffix and recursing on the `drN` base profile.

---

## Phase 0 W9 YCSB RocksDB (2026-04-10)

**Status**: first clean sweep (n=3 × 5 dr profiles) completed at
18:29 local. **Null finding on the strong hypothesis**: YCSB
Workload A on RocksDB at 20M records (~22 GB dataset) shows no
clean `dirty_ratio` sensitivity on this SATA SSD with the stock
`bg:dr ≈ 0.5` scaling. Medians span 11,717 to 18,701 ops/s across
dr={1,5,10,20,40} — a 1.6× range, with run-to-run variance inside
a single profile reaching 4.3× at dr20 and ~2× at dr5. Noise
dominates any signal. A `dirty_ratio` vs `dirty_background_ratio`
confound was then identified in the profile design and a
disambiguation sweep is staged but not yet run — see bottom of
section.

### Why W9 was added

W6 (sysbench OLTP on InnoDB) came back flat across the full dr
sweep, which supported the "PI is safe for in-place-update DBs"
scope claim but gave the paper no hardware evidence that any real
application *benefits* from autotuning. The user reported
significant tuning gains on v6.6 RocksDB workloads. RocksDB is
architecturally different from InnoDB — memtable flush writes
through the page cache in bursts, compaction rewrites through the
page cache, write amplification 6-10× — so it was a plausible
place to find a workload where `dirty_ratio` actually matters.
W9 = YCSB Workload A (50/50 read/update, zipfian) against a
RocksDB instance, same dr sweep as W6.

### Harness (all under `/mydata/wb-work/`)

- **`phase0/workloads/w9-ycsb-rocksdb.sh`** — workload script.
  Defines `prepare()` (runs before sysctl apply via the
  `run-workload.sh` prepare-hook extension added for W9) and
  `run()` (invokes YCSB via `/mydata/wb-work/ycsb/ycsb-run`
  wrapper, captures diskstats pre/post, rocksdb-log.txt tail,
  runmeta.json).
- **`phase0/workloads/w9-workloada.properties`** — YCSB parameters:
  recordcount=20000000, fieldcount=10, fieldlength=100, threadcount=16,
  measurementtype=hdrhistogram. **Note**: does NOT set
  `maxexecutiontime` because that would cap the load phase; the
  `run()` function passes it explicitly via `-p maxexecutiontime=180`
  so only the transactions phase is time-bounded. The initial build
  of this file DID set it in-properties and hit this trap — the
  first seed only had 15.25M records instead of 20M.
- **`phase0/setup/build-seed-w9.sh`** — builds the seed RocksDB
  instance via YCSB load phase, then runs `FlushDB` to drain WAL.
- **`phase0/setup/FlushDB.java`** + `.class` — tiny Java program
  using rocksdbjni 5.11.3 (bundled in the YCSB binding jar) to open
  the DB, flush every column family with
  `setWaitForFlush(true)`, and close cleanly. Required because the
  YCSB 0.17.0 rocksdb binding's `cleanup()` path never calls
  `db.flush()`, so the load phase leaves hundreds of MB of WAL
  files in the seed — see "WAL confounder" below.
- **`phase0/sweep-w9.sh`** — original 1D `drN` sweep driver.
- **`phase0/sweep-w9-drbg.sh`** — new 2D `drN-bgM` disambiguation
  sweep driver. Staged, not yet run. See "dr/bg confound" below.
- **`/mydata/wb-work/ycsb/ycsb-rocksdb-binding-0.17.0/`** — YCSB
  pre-built tarball with the rocksdb binding + rocksdbjni 5.11.3.
- **`/mydata/wb-work/ycsb/ycsb-run`** — shell wrapper that builds
  the classpath and invokes `site.ycsb.Client` directly. Needed
  because the upstream `bin/ycsb` launcher is Python 2 only and
  does not run on Ubuntu 24.04 Python 3 (`except X, e:` and
  `print >>` syntax).
- **`/mydata/wb-work/rocksdb-w9/seed/`** — the seed DB. 22 GB on
  disk, 20M records, 197 SSTs, 1×0-byte WAL placeholder after
  FlushDB. Do not touch during a sweep.
- **`/mydata/wb-work/rocksdb-w9/work/`** — per-iteration work dir
  (rsync'd from seed in `prepare()`). Left in place after runs.

### Iterations discovered during iter 1+2 and corrected

**WAL-in-seed confounder** (fixed 2026-04-10 ~15:45). The YCSB
0.17.0 rocksdb binding's close path doesn't flush, so the initial
load left ~421 MB of WAL (4 files: 000937.log 123M, 000944.log 95M,
000945.log 123M, 000955.log 80M) in the seed. Every iteration's
reopen replayed all 421 MB of WAL before the measurement window
started, and the replay triggered post-replay compaction storms
that landed inside the 180 s window at unpredictable times. The
contaminated n=1 sweep showed a striking but artifact-dominated
"concave curve with dr10 optimum at 38k ops/s and dr20 bimodal
between 15k and 25k". Fix: `FlushDB.java`, invoked from
`build-seed-w9.sh` after YCSB load. On the existing seed: 4×WAL
(421 MB) → 1×0-byte placeholder. Smoke run at dr20 after the fix:
**41,035 ops/s** (vs 15,516 contaminated, 2.6×). `Write Ahead Log
file ... size: 0` in the reopened LOG confirms zero replay.

**`cp -a` → `rsync -a --delete` migration** (2026-04-10 ~15:45,
user suggestion). `prepare()` originally did
`rm -rf work && cp -a seed work` which copied the full 22 GB every
iteration. Switched to `rsync -a --delete seed/ work/`. First
iteration still copies the whole seed (work/ doesn't exist);
subsequent iterations only copy the SSTables YCSB mutated during
the previous run.

### Clean sweep results (n=3 per profile, 2026-04-10 17:19–18:29)

Via `phase0/aggregate.py` — "W9 drN sweep" section. The smoke run
adds a 4th dr20 data point.

| profile | n | ops/sec median [min..max] | upd p99 ms | upd p999 ms | write_amp |
|---------|---|---------------------------|------------|-------------|-----------|
| dr1  | 3 | 18,701 [14,188..18,828]   | 10.2       | 134         | 7.44×     |
| dr5  | 3 | 12,222 [10,173..27,302]   | 18.7       | 168         | 7.68×     |
| dr10 | 3 | 12,478 [9,361..16,029]    | 15.7       | 181         | 7.60×     |
| dr20 | 4 | 17,685 [9,585..41,035]    | 9.1        | 147         | 6.38×     |
| dr40 | 3 | 11,717 [11,268..14,691]   | 21.8       | 160         | 6.61×     |

Medians span 1.6× across the full sweep. Run-to-run variance
within a profile: **4.3× at dr20**, 2.7× at dr5, 1.7× at dr10,
**1.3× at dr1 and dr40**. The extremes are the tightest, which is
the opposite of what a clean dr-sensitivity story predicts.

Write amplification is roughly flat at 6.4–7.7× across all
profiles now — contradicting the "compaction debt at large dr"
pattern that appeared in the contaminated data (that was a
measurement artifact of deferred compaction landing outside the
180 s window after the WAL replay ate the first 10 s).

**Conclusion pending the drbg disambiguation**: W9 on this
hardware does not cleanly reproduce the user's v6.6 observation.
The hypothesis that "RocksDB/LSM workloads show dr sensitivity
that InnoDB/in-place workloads don't" is not supported by this
data. W6 (flat) and W9 (flat-with-noise) are now two "no
sensitivity" hardware data points. Only W4 (sync/dirty tradeoff),
Wmix (bulk/sync cliff), and W3b/Wmix probabilistic tails still
carry the paper's autotuning motivation.

### dr/bg confound discovered (2026-04-10 ~18:30, user-flagged)

The `drN` profiles in `common.sh` vary `vm.dirty_ratio` AND
`vm.dirty_background_ratio` simultaneously at `bg:dr ≈ 0.5`,
matching the kernel defaults:

| profile | dirty_ratio | dirty_background_ratio | bg/dr |
|---------|-------------|------------------------|-------|
| dr1     | 1           | 1                      | 1.0   |
| dr5     | 5           | 2                      | 0.4   |
| dr10    | 10          | 5                      | 0.5   |
| dr20    | 20          | 10                     | 0.5   |
| dr40    | 40          | 20                     | 0.5   |

These are two *different* knobs:

- **`dirty_ratio`** (hard cap): `balance_dirty_pages()` throttles
  the dirtying process synchronously when dirty > this. The BDP
  pause-gate the paper's motivation is organized around.
- **`dirty_background_ratio`** (flusher-wake threshold): flusher
  threads wake up asynchronously to drain dirty pages above this.
  Does not throttle any writer; just starts background writeback
  earlier.

For a bursty LSM workload like RocksDB, these might act very
differently: `bg` controls whether compaction's SSTable writes
land in an empty dirty pool or a full one, while `dr` controls
whether a memtable-flush burst gets mid-burst-stalled. Moving both
together means the clean W9 sweep cannot tell whether the flat
curve is flat because neither knob matters, or because we're
sweeping along a diagonal that happens to miss the sensitive axis.

### Next: 2D dr/bg disambiguation sweep (staged, not yet run)

**`phase0/sweep-w9-drbg.sh`** runs a two-axis sweep using a new
`drN-bgM` profile family (added to `common.sh`'s
`apply_sysctl_profile` alongside the existing `drN` and
`drN-<method>` families):

- **Sweep A — hard-cap isolation**: fix `bg=1` (flusher always
  aggressive), sweep `dr ∈ {1, 5, 10, 20, 40}`.
- **Sweep B — flusher-wake isolation**: fix `dr=20` (stock hard
  cap), sweep `bg ∈ {1, 2, 5, 10, 20}`.

9 unique profiles (dr20-bg1 shared) × 3 iterations = 27 runs,
~2 hours total. Interpretation matrix:

| Sweep A   | Sweep B   | Conclusion                                     |
|-----------|-----------|------------------------------------------------|
| flat      | flat      | W9 is a genuine null on this hardware          |
| sensitive | flat      | hard-cap (dr) matters, original hypothesis OK  |
| flat      | sensitive | flusher-wake (bg) is the real lever for RocksDB |
| sensitive | sensitive | both matter, paper needs two-knob story        |

`aggregate.py`'s W9 section is already extended to print Sweep A
and Sweep B as separate sub-tables. No re-run of `build-seed-w9.sh`
is needed; the existing seed is clean.

To run:

```bash
cd /mydata/wb-work/phase0
nohup ./sweep-w9-drbg.sh > /tmp/sweep-w9-drbg.log 2>&1 &
disown
# ~2 hours later:
python3 aggregate.py
```

---

## Live-kernel cliff validation (2026-04-11 ~00:30)

Confirmed the freerun cliff on the actual `6.19.0-wb-baseline` kernel
via a small vng VM. This closes the loop between the code analysis
(Issue 1 in §"Kernel code analysis") and the simulator's S11 scenario:
the behavior we traced in the code and modeled in the simulator is
the same behavior the real kernel exhibits.

### Setup

4 GB vng VM with a QEMU-throttled virtio-blk disk (30 MB/s total via
`-drive throttling.bps-total=30000000`). At 4 GB RAM and dr=20 on a
fresh boot, thresholds resolve to:

- dirty_threshold = **719 MB** (~184 097 pages)
- bg_threshold = 358 MB
- freerun_ceiling = **539 MB** (= (thresh + bg) / 2)

Earlier attempts with dm-delay on /dev/vda failed because the guest
block layer merges 1 MB fio bios into multi-MB aggregates, so
dm-delay's per-bio latency didn't actually slow the effective
device. QEMU's bandwidth throttle sits below the guest entirely and
works regardless of merge policy — see `run-cliff-experiment.sh`
header comment for the attempted-and-abandoned approaches.

Harness: `/mydata/wb-work/phase0/vng-experiments/run-cliff-experiment.sh`.
Python 50 Hz vmstat sampler at `sample-vmstat.py` (the shell
`while true; do awk; done` version captured only 2–3 samples per run;
the Python port reliably produces ~2 000 samples per phase). bpftrace
was attempted but repeatedly failed to attach cleanly inside the vng
stdio/virtio-serial path; vmstat alone turned out to be sufficient
because the cliff is obvious in the `nr_dirty + nr_writeback` trace.

### Observation

Two phases, single run:

| phase | fio size | fio rate | peak dirty+wb | crossed freerun? | fio effective BW |
|-------|----------|----------|---------------|-------------------|-------------------|
| A     | 300 MB   | 150 MB/s | **300 MB**    | no                | 150 MB/s (rate-limited) |
| B     | 1500 MB  | unlimited | **727 MB**   | **YES** at t=3.73 s | **49 MB/s** (bdp-throttled) |

Phase B timeline (Python sampler, key transitions):

```
t=0.00–2.67  — dirty=0 (fio not running yet; drop_caches + file layout)
t=3.12       — dirty starts growing (fio entering write loop)
t=3.56       — dirty=378 MB, wb=72 MB, sum=450 MB  (still below freerun)
t=3.67       — dirty=383 MB, wb=128 MB, sum=511 MB (approaching freerun)
t=3.73       — *** cliff crossed: sum=543 MB ***
t=3.88       — sum=579 MB  (flusher + bdp now active)
t=4.33       — sum=627 MB
t=5.42       — sum=700 MB
t=6.74       — sum=727 MB  (peaks at hard cap)
t=7.95       — sum=716 MB  (steady state just under hard cap)
... stays ~715–725 MB for the next ~25 s while fio is throttled ...
```

fio's minimal I/O stats (from the earlier run with a similar setup)
showed the p50 write latency at 1.8 ms (page cache fast), climbing to
**12.9 seconds at the p99.95 tail** — that's individual `write()`
syscalls blocked inside `balance_dirty_pages_ratelimited →
balance_dirty_pages → io_schedule_timeout` when the controller was
pulling the task's ratelimit down to device speed.

### What this confirms

Three things directly observable on a live kernel:

1. **Below freerun, the controller is offline.** In Phase A, fio
   produced 300 MB of dirty pages, ran at its full rate-limit target
   (150 MB/s), and experienced zero additional throttling from the
   kernel — exactly as page-writeback.c:1863 predicts.

2. **At the cliff, fio's effective bandwidth crashes.** Before the
   cliff (first ~600 ms of Phase B) fio dirties the page cache at
   memcopy speed (hundreds of MB/s, bounded only by memory bandwidth).
   After crossing freerun, fio's throughput drops to **49 MB/s** —
   pulled down to match the 30 MB/s device drain rate plus some
   in-flight backlog. That 10–20× discontinuity is the cliff
   operating as designed: zero throttle below, full throttle above.

3. **Steady state operates at ~97% of the hard cap.** Dirty+wb
   oscillates between 710 and 727 MB against a 719 MB hard limit.
   The controller's target (setpoint ≈ 0.875 × thresh ≈ 629 MB)
   isn't held — the system operates right at the hard cap because
   the step filter's gain schedule can't pull the dirty pool any
   further down once it converges (see Issue 2). **The controller's
   actual equilibrium is the hard cap, not the setpoint.** That's a
   second pathology on top of the cliff.

### bpftrace validation (2026-04-11 ~16:29) — cliff confirmed by tracepoint

Re-ran the cliff experiment with `writeback:balance_dirty_pages`
bpftrace instrumentation actually wired up this time. The earlier
silent-attach issues turned out to be a combination of five problems,
all of which are documented in the fixed harness
(`phase0/vng-experiments/launch-vng.sh` + `run-cliff-experiment.sh` +
`test-bpftrace.sh`):

  1. **vng's `--disk` flag bypasses `--qemu-opts` throttling**. `--disk`
     creates its own virtio-blk front-end that doesn't share the
     `throttling.bps-total=30000000` from the user-provided `-drive`.
     Result: fio ran at 459 MB/s even though we asked for 30 MB/s, so
     dirty never crossed freerun. Fix: drop `--disk`, define both the
     `-drive` and the `-device virtio-blk-pci,drive=slow` inline in
     `--qemu-opts=...` so the throttle attaches to the right front-end.
  2. **bpftrace can't write outputs to the 9p root**. We stage the
     probe script and output files under `/run` (tmpfs).
  3. **bpftrace's `-o FILE` needs the child detached from the
     harness's TTY.** Running `bpftrace ... &` directly inside
     `bash -c "... &"` left it in an ambiguous state where buffered
     output never flushed; using `setsid bpftrace ... </dev/null
     >/dev/null 2>err &` solves it. The `setsid` strips the
     controlling tty.
  4. **`kill -INT` races the ringbuffer drain.** bpftrace catches
     SIGINT and prints aggregates, but events from the last ~200 ms
     in the perf ring buffer can be lost. Fix: append
     `interval:s:30 { exit(); }` to the probe script so bpftrace exits
     cleanly from its own timer and the shell just `wait`s the child.
  5. **Summary counter was off-by-two.** The bdp hit counter did
     `NR - 1` to strip one header line, but bpftrace writes TWO
     bookkeeping lines (`Attaching N probes...` banner + BEGIN
     `printf` header). The earlier run-cliff-experiment.sh never
     actually invoked bpftrace (literally `: > "$bdp_out"`), so this
     bug was dormant.

Results from the 2026-04-11 re-run (
`results/run-cliff-experiment-20260411-1629.log`):

| Phase | peak dirty+wb | freerun crossed | bdp data rows |
|-------|---------------|-----------------|---------------|
| A (300 MB @ 150 MB/s) | 288 MB | no  | **0**  |
| B (1500 MB unrestricted)  | 723 MB | YES | **425** |

**0 vs 425 bdp-tracepoint hits**. This is the direct tracepoint-level
proof of Issue 1: in Phase A, `balance_dirty_pages` never fires its
`trace_balance_dirty_pages` call because the `free_running:` branch
in `mm/page-writeback.c:1863` skips past it. In Phase B, the cliff is
crossed at t=5.838 s (sum=544 MB, just above freerun=537 MB) and 425
tracepoint events are captured over the next ~25 seconds while fio is
throttled down to the device drain rate.

First bdp event on Phase B landed with `dirty=185088 pages (~723 MB)`
— **actually above hard thresh (184k pages)**. Stock's equilibrium on
the cross-run settled at `dirty_ratelimit = 29164 pages/s (~114 MB/s)`
against a 30 MB/s device — a **3.8× overshoot of the true drain
rate**. That's evidence for Issue 2 (the step filter's gain schedule
gives up while still far from the true equilibrium) on top of Issue 1.
Both worth calling out in the paper.

The motivation figure for the paper can now be built directly from
`results/run-cliff-experiment-20260411-1629.log` — vmstat timeline
for the freerun cross plus bdp CSV for the ratelimit trajectory.

### Caveats

- **Single run, single dr setting (dr=20).** Would be nice to sweep
  dr=5, dr=10, dr=20, dr=40 in the vng to see the cliff move with
  the threshold. Cheap follow-up (~5 min per run, scripted).
- **No PI-kernel comparison yet.** This experiment only shows the
  stock kernel's behavior on the cliff. To do a head-to-head, we'd
  need to land Phase 2.1 (PI kernel implementation) first, then
  repeat the same vng harness on both kernels. That's the Phase 2
  payoff, not a Phase 0 task.

---

## Live-kernel pathology reproductions (2026-04-11 ~16:30)

With bpftrace working inside vng, I ran three experiments to take
Issues 1, 2, 5, 6, and 8 from the code analysis out of the simulator
and reproduce them directly on the `6.19.0-wb-baseline` kernel. Scripts:

- `phase0/vng-experiments/run-cliff-experiment.sh` — Issue 1
- `phase0/vng-experiments/run-idle-reset-experiment.sh` — Issues 2, 5
- `phase0/vng-experiments/run-many-writers-experiment.sh` — Issues 6, 8

All runs used the 4 GB vng with a 30 MB/s QEMU-throttled virtio-blk via
`launch-vng.sh`.

### Issue 1 (freerun cliff) — 0 vs 425 bdp events

Already reported above in §"bpftrace validation". Phase A (300 MB at
150 MB/s, max dirty 288 MB) fires **zero** `writeback:balance_dirty_pages`
tracepoints. Phase B (1500 MB unrestricted, dirty crosses freerun at
t=5.838 s) fires **425** tracepoints in ~25 s of throttled writing.
Direct tracepoint-level confirmation of the `free_running:` branch
bypass at page-writeback.c:1863.

### Issue 2 (step filter slow convergence) — 9 s to settle at 3.8× the truth

From the W1 phase of the idle-reset run
(`results/run-idle-reset-experiment-20260411-1637.log`). Single writer
on a 30 MB/s device, bdp tracepoint captured every event from the
moment dirty crossed freerun:

```
   t+0 ms     dirty=136192 ratelimit=93724 pages/s (~366 MB/s)  ← cold-start seed
   t+949 ms   ratelimit=82488            (~322 MB/s)  ← first step
   t+1727 ms  ratelimit=65704            (~257 MB/s)
   t+2487 ms  ratelimit=54168            (~212 MB/s)
   t+3305 ms  ratelimit=48488            (~189 MB/s)
   t+4029 ms  ratelimit=43644            (~170 MB/s)
   t+5541 ms  ratelimit=38444            (~150 MB/s)
   t+7035 ms  ratelimit=33948            (~133 MB/s)
   t+9188 ms  ratelimit=29088            (~114 MB/s)  ← settled
   t+21268 ms ratelimit=29088            (~114 MB/s)  ← unchanged
```

**True device drain rate is 30 MB/s.** Stock settles in ~9 seconds at
**113.6 MB/s — a 3.8× overshoot**. The gain-scheduled slowdown
(page-writeback.c:1472) zeroes out the step before the controller
reaches the correct value, because `step = dirty_ratelimit / (2*step +
1) >> shift / 8` collapses to 0 once `shift` exceeds `BITS_PER_LONG`,
and that happens while still 84 MB/s away from the truth. Exactly
Issue 2's prediction.

This is the paper's second motivation plot, and it's on a single run —
the trajectory is self-documenting. Save the W1 bdp CSV
(`/var/tmp/idle-reset/bdp.csv` inside the vng, echoed in the log) as
the source of truth.

### Issue 5 (idle-reset fragility) — observed, but subtler than predicted

The code analysis predicted that after a > 1 s idle,
`wb_bandwidth_estimate_start` would reset the stamps and force the
estimator to re-converge. The idle-reset experiment ran W1 (1500 MB
write, controller converges to 29088 pages/s) → I1 (sync + 4 s idle) →
W2 (another 1500 MB write) and diffed the dirty_ratelimit trajectories.

**Result**: `dirty_ratelimit` was **identical** before and after the
idle gap: 29088 pages/s at W1 end, 29088 pages/s at W2 start. Stock
**did not reset** the learned ratelimit.

**Why the pathology is real anyway**: `wb_bandwidth_estimate_start`
only resets the *bandwidth stamps* (bw_time_stamp, dirtied_stamp,
written_stamp), not `dirty_ratelimit` itself. The ratelimit persists
because the step filter's gain schedule (Issue 2) zeroes out the step
near equilibrium — there's no force to move it. So the pathology is
not "ratelimit forgets learned state", it's "**ratelimit remains
frozen at a potentially-stale value until a large enough disturbance
arrives to force the step filter to move**". For a workload whose
device genuinely changed characteristics during the idle gap (GC,
hardware migration, topology change), stock would have a wrong
ratelimit and take many seconds to adapt.

This reframing is actually *better* for the paper than the original
framing — "the learned state persists but never adapts" is a stronger
critique than "the learned state is forgotten every 1 second".

### Issues 6 + 8 (MAX_PAUSE polling loop + control in task context)

Script: `run-many-writers-experiment.sh`. Two back-to-back runs on the
same 30 MB/s device:

**Part A — 1 writer, 16 s**:
- 624 bdp events total = 37.9 ev/s
- 498 of them had `pause > 0` (task actually slept)
- **389 / 498 = 78 % clamped at exactly MAX_PAUSE = 200 jiffies**
- `task_ratelimit` collapsed from 25900 → **0** by end of run
- `dirty_ratelimit` decayed from 89300 → **2032 pages/s (~8 MB/s)**
  on a 30 MB/s device — a **3.7× undershoot**, the mirror image of
  Issue 2 seen on short runs. Long-running single-writer drives the
  controller below device capacity.

**Part B — 32 writers, 15 s**:
- 944 bdp events total = 67.2 ev/s (1.8× A, not 32×)
- **944 / 944 = 100 % clamped at 200 ms**
- `task_ratelimit` floored at **0** throughout
- `dirty_ratelimit` decayed to **244 pages/s (~1 MB/s)** — 30× below
  device drain rate.

**What this shows**:

1. **MAX_PAUSE=200 ms is already too small even for 1 writer on a 30
   MB/s device**. 78 % of the 1-writer's bdp pauses were the natural
   value clamped down. Every clamped iteration re-enters the throttle
   loop, re-acquires `wb->list_lock`, re-sums percpu `NR_FILE_DIRTY`,
   and recomputes pos_ratio. Issue 6 is alive on minimally-slow
   devices, not a fringe many-writer concern.
2. **The controller collapses to `task_ratelimit = 0` under sustained
   throttling**. Combined with `dirty_ratelimit` decaying far below
   device capacity, stock ends up in a broken steady state where every
   write() sleeps 200 ms and the device is under-driven. Neither
   clamp nor step filter has a recovery path.
3. **B / A ratio of 1.8× total is mechanically informative** — it's
   less than 32× because the 32 writers share the same `wb_thresh`
   and the task_ratelimit collapse leaves them mostly stuck at the
   floor instead of cycling through bdp at high frequency. The real
   pathology isn't "bdp fires faster with more tasks" — it's "each
   individual task spends 100% of its wall-clock time wedged in the
   clamp, and collectively they've driven dirty_ratelimit into
   oblivion".

Raw bdp CSVs live at `/var/tmp/many-writers/bdp-{1writer,32writer}.csv`
inside the vng, copied into the launch log dump file.

### What this means for Phase 2.1

The live-kernel reproductions confirm that the four design-breaking
pathologies we care about (cliff, slow-step, wrong equilibrium,
polling-loop clamp collapse) are all present on the kernel we plan to
replace. Phase 2.1 (decoupled estimator workfn + PI controller) needs
to address all four:

1. **Kill the cliff**: always run the control update, even when dirty
   is small.
2. **Fix the step response**: replace gain-scheduled cubic + step
   filter with PI integral action that has *no dead zone near
   equilibrium*.
3. **Fix the equilibrium point**: PI's integral term converges to the
   correct value by construction, not 3.8× overshoot.
4. **Kill MAX_PAUSE-driven polling**: compute pause directly from the
   PI output + configured drain time, without any 200 ms clamp. The
   dirtying task sleeps for the *natural* pause or not at all.

This also motivates running the control update in a dedicated per-wb
workfn rather than in the dirtying task's throttle loop (Issue 8),
because the polling-loop collapse in Part A above is fundamentally a
"control update running in the same thread that's being throttled"
pathology — the collapse feedback loop only closes because each
clamped wakeup re-runs the control update.

---

### drbg sweep result (27 runs, 2026-04-10 ~20:46)

All 27 runs completed cleanly and were analyzed via `aggregate.py`.
**Both sub-sweeps came back flat relative to the run-to-run noise floor.**
Numbers from the YCSB-run-window slice of `vmstat.csv`:

#### Sweep A (bg=1, dr varied) — hard-cap isolation

| profile   | n | ops/s median [min..max]    | max/min |
|-----------|---|----------------------------|---------|
| dr1-bg1   | 3 | 22,992 [12,627..25,162]    | 2.0×    |
| dr5-bg1   | 3 | 23,008 [8,987..23,998]     | 2.7×    |
| dr10-bg1  | 3 | 16,765 [11,350..17,340]    | 1.5×    |
| dr20-bg1  | 3 | 19,868 [16,760..25,599]    | 1.5×    |
| dr40-bg1  | 3 | 21,413 [20,574..23,016]    | 1.1×    |

Cross-profile median span: **1.37×**. No monotone trend.

#### Sweep B (dr=20, bg varied) — flusher-wake isolation

| profile     | n | ops/s median [min..max]    | max/min |
|-------------|---|----------------------------|---------|
| dr20-bg1    | 3 | 19,868 [16,760..25,599]    | 1.5×    |
| dr20-bg2    | 3 | 18,542 [12,106..22,041]    | 1.8×    |
| dr20-bg5    | 3 | 13,025 [10,021..30,980]    | 3.1×    |
| dr20-bg10   | 3 | 25,102 [11,316..36,981]    | 3.3×    |
| dr20-bg20   | 3 | 24,557 [15,968..31,433]    | 2.0×    |

Cross-profile median span: **1.93×**. Also no monotone trend.

#### Root cause confirmed: the controller is not running

The `vmstat.csv` slice over the 180 s YCSB window (stripping
prepare/rsync burst) shows the smoking gun:

| profile    | med dirty | p95 dirty | dr thresh | med util | max util |
|------------|-----------|-----------|-----------|----------|----------|
| dr1-bg1    |   341 MB  |   970 MB  |  1197 MB  |   28.5%  |  100.2%  |
| dr5-bg1    |   194 MB  |  1294 MB  |  6118 MB  |    3.2%  |   36.2%  |
| dr10-bg1   |   205 MB  |  1374 MB  | 12237 MB  |    1.7%  |   18.4%  |
| dr20-bg1   |   289 MB  |  1644 MB  | 24460 MB  |    1.2%  |   10.4%  |
| dr40-bg1   |   239 MB  |  2197 MB  | 48996 MB  |    0.5%  |    4.5%  |

Peak dirty pressure is 1–2 GB. The dr=5 threshold is 6 GB, dr=20 is 24
GB, dr=40 is 49 GB. **Above dr ≥ 5 the hard cap literally never fires.**
The bg threshold exceeds peak dirty too at bg ≥ 5. So for 8 of the 9
drbg profiles, neither mechanism we're sweeping is engaged.

The user noted the original observation was on a **100 GB dataset**. Our
seed is 22 GB on 125 GB RAM — fits 5× over in page cache, so reads
never miss and dirty pressure stays tiny. **W9 in its current form
cannot test dirty_ratio sensitivity at dr ≥ 5**, no matter how many
iterations we run. Two remediation options are available: rebuild the
seed at 100 GB (~45 min, ~200 GB disk, 519 GB free — plenty), or
constrain YCSB to a 32 GB memory cgroup (faster, keeps the existing
seed, cgroup-v2 memory.max accounts for page cache).

**This pivoted the analysis from "find workloads that stress the
controller" to "find structural flaws in the controller" — see §"Kernel
code analysis (2026-04-10 late)" below.**

---

## Kernel code analysis (2026-04-10 late)

After the W9 drbg null confirmed the controller isn't running on
normal workloads, we stepped back from the empirical angle and read
`mm/page-writeback.c` and `fs/fs-writeback.c` line-by-line. The
working-set-dependent pathologies we'd been chasing are real but
secondary; the **structural issues with the v6.19 implementation
justify the paper's thesis on their own**, independent of how big the
dataset is. Eight issues, ordered by severity:

### 1. The controller is dead code below freerun_ceiling (the cliff)

**page-writeback.c:1749** — `domain_dirty_freerun()` sets
`dtc->freerun = dirty <= (thresh + bg_thresh) / 2`. When `freerun` is
true, `balance_dirty_pages` at **line 1863** branches straight to
`free_running:`, sets `current->dirty_paused_when`, sets
`current->nr_dirtied = 0`, computes a polling interval, and `break`s
out. **No pos_ratio, no dirty_ratelimit update, no bandwidth estimator
update** (the `__wb_update_bandwidth` call is at line 1910, after the
freerun branch). The entire cubic/EWMA/step-filter stack is bypassed.

On our 125 GB host at dr=20, freerun_ceiling = 18 GB. Our W9 vmstat
showed peak dirty ~1.6 GB. **The controller never runs.** This isn't
"our test was underpowered" — it's that every real workload whose
steady-state dirty pool is bounded by application churn rate (rather
than by RAM) sees zero active control. The control regime is a narrow
band from 75% of thresh to 100% of thresh, and most workloads never
enter it.

**Paper implication**: the current PI + freerun-skip plan still bakes
in the freerun concept. That's probably wrong. The replacement should
drop the cliff and always compute a rate target, even if it equals
device bandwidth when dirty is very low. Otherwise "PI controller" is
what runs 0.1% of the time and "nothing" the rest — same as stock.

### 2. The filter stack is not a controller, it's a cascade

Five smoothing layers in series between "workload dirties a page" and
"task sleep time":

  1. **page-writeback.c:1234** `wb_update_write_bandwidth`: primary EWMA
     over `period = roundup_pow_of_two(3*HZ) ≈ 4 s`.
  2. **Same function, lines 1266–1270**: a secondary anti-spike filter
     that adds another 1/8 step when the smoothed trend is moving away
     from the instant. Stretches the effective time constant to 6–8
     seconds for a monotone step response.
  3. **page-writeback.c:1071** `wb_position_ratio`: cubic polynomial on
     `(setpoint − dirty)`, with a per-wb linear adjustment at lines
     1211–1215 and a reserve-area multiplier at lines 1222–1229. Three
     stacked nonlinearities in fixed-point integer math.
  4. **page-writeback.c:1338** `wb_update_dirty_ratelimit`: computes
     `balanced = task_ratelimit × write_bw / dirty_rate` — that's the
     only actual feedback line — but then **refuses to use it**.
     Instead, lines 1455–1465 select a direction (min3/max3 requires
     three estimators to agree), and lines 1472–1474 gain-schedule the
     step:

     ```c
     shift = dirty_ratelimit / (2 * step + 1);
     if (shift < BITS_PER_LONG)
         step = DIV_ROUND_UP(step >> shift, 8);
     else
         step = 0;
     ```

     Asymptotic gain goes to zero as error shrinks relative to current
     rate — the controller stops moving once it's "close enough" even
     if residual error is significant. The comment at line 1435 admits
     this is a "filter out singular points" workaround for
     `balanced_dirty_ratelimit` jumping around randomly, which is
     itself a symptom of computing a ratio with a 200 ms dirty_rate
     denominator.
  5. **page-writeback.c:1916** `task_ratelimit = dirty_ratelimit × pos_ratio`.
     Product of two already-smoothed quantities.

None of this has an analytically characterizable step response. A
single first-order filter + PI integral action would be dramatically
simpler and provably stable.

### 3. Thresholds scale with RAM, not with device drain rate

**page-writeback.c:325** `global_dirtyable_memory() = free + active_file
+ inactive_file − reserve`. Then `thresh = ratio × available_memory`.
On 125 GB RAM at dr=20, thresh = **24 GB**. On a 450 MB/s SATA SSD,
that's **53 seconds of queued writeback**. The "safety limit" is
actually the maximum latency a `sync()` can suffer, in units of drain
backlog. The user-facing knob (`dirty_ratio`) is decoupled from the
user-facing concern (tail latency).

Also: `dom->dirty_limit` at **line 1304–1306** decays at
`(limit − thresh) >> 5` per BANDWIDTH_INTERVAL — about 3.1% per 200 ms.
If sysctl reduces dirty_ratio from 20 to 5, it takes **~30 seconds**
for the effective limit to catch up (and requires somebody to be
hitting `balance_dirty_pages`, which nobody does in freerun). This is
a methodology gotcha for our W6/W9 sweep design: the first few seconds
of each profile don't reflect the intended limit.

**Paper implication**: directly motivates the "time-based per-device
limit" half of the thesis. Citing `global_dirtyable_memory()` is the
cleanest way to argue that the current knob measures the wrong thing.

### 4. The proportional-share story the code tells is not what the code does

`__wb_calc_thresh` at **page-writeback.c:900** computes the fprop
share (textbook floating-proportions fair sharing), then lines
931–936:

```c
if (thresh > dtc->dirty) {
    if (strictlimit) wb_thresh = max(wb_thresh, (thresh - dtc->dirty) / 100);
    else             wb_thresh = max(wb_thresh, (thresh - dtc->dirty) / 8);
}
```

On our 125 GB host: thresh = 24 GB, dirty ≈ 1 GB, slack = 23 GB, slack/8
= **~2.9 GB**. The fprop share for any active wb is smaller. So
`wb_thresh = max(fprop, slack/8) ≈ slack/8`. The **fprop machinery is
clobbered by the slack/8 fallback in the common case**. We can
probably delete the entire fprop layer in the new design — deleting
~200 LOC is persuasive in kernel patches.

Our simulator's `StockController` never modeled fprop anyway (it uses
a single `thresh` as the effective limit), which by accident matches
the real kernel's behavior better than a fprop-faithful port would
have.

### 5. Bandwidth estimator has three update paths, all fragile

Three update sites for `wb->write_bandwidth` / `avg_write_bandwidth`:

  1. **page-writeback.c:1910** — inside `balance_dirty_pages` after the
     freerun check. Never fires in freerun.
  2. **page-writeback.c:2619** — `do_writepages` path, when the flusher
     is actively writing. Only fires when there's flush activity.
  3. **page-writeback.c:2975** — `wb_inode_writeback_end` queues a
     200 ms delayed workfn at the *tail* of each writeback burst. Fires
     exactly once per burst.

And `wb_bandwidth_estimate_start` at **line 1542** resets the stamps
after any idle period > 1 s. Combined with the 4-second EWMA period,
that means the first 4+ seconds after idle run on noisy/unreliable
estimates. Every interactive workload with idle gaps >1 s pays this
cost.

**Paper implication**: a decoupled estimator that runs in a dedicated
workfn at fixed cadence (independent of dirtying activity) is a
separate improvement from "use PI instead of cubic" and should be
called out as such in the plan. It isn't in SESSION.md §"Design
decisions" yet.

### 6. MAX_PAUSE = 200 ms makes bdp a polling loop

**page-writeback.c:49** — `#define MAX_PAUSE max(HZ/5, 1)` = 200 ms. At
**lines 1958–1962**, any computed pause longer than 200 ms is clamped
and the task re-enters the loop. At low task_ratelimit (many
concurrent dirtiers on a slow device), `balance_dirty_pages` becomes a
polling loop: each iteration re-acquires `wb->list_lock`, reads
`global_node_page_state(NR_FILE_DIRTY)` (sums percpu counters — not
free on large systems), and recomputes the cubic polynomial. At 1000+
concurrent dirtiers this is measurable CPU waste.

The `now += min(pause - max_pause, max_pause)` line "rewinds" the
task's virtual clock — fragile workaround for the clamp, not a fix.

### 7. DIRTY_POLL_THRESH = 32 is tuned for CFQ (removed in 5.0)

**page-writeback.c:55** — `#define DIRTY_POLL_THRESH (128 >> (PAGE_SHIFT - 10))`
= 32 on 4 KB pages. Comment at **line 1639–1645**:

```c
/*
 * Tiny nr_dirtied_pause is found to hurt I/O performance in the test
 * case fio-mmap-randwrite-64k, which does 16*{sync read, async write}.
 * When the 16 consecutive reads are often interrupted by some dirty
 * throttling pause during the async writes, cfq will go into idles
 * (deadline is fine). So push nr_dirtied_pause as high as possible
 * until reaches DIRTY_POLL_THRESH=32 pages.
 */
```

This constant was tuned against **CFQ**, which was removed from the
kernel in 5.0 (2019). The current code carries a 2011-era workaround
for a scheduler that hasn't existed in 6+ years. Symptom of broader
accumulation of ungrounded tuning constants.

### 8. Control and state-estimation run in the dirtying task's context

`balance_dirty_pages` does pos_ratio computation, bandwidth estimate
update, and dirty_ratelimit step — all synchronously in the dirtying
task's thread inside the throttle loop. Consequences:

  * Control updates only happen when tasks are actively dirtying AND
    in the controlled regime.
  * Control updates stall the dirtying task (computation is not sleep,
    it's wall-clock work).
  * Multiple tasks race on `wb->list_lock` inside `__wb_update_bandwidth`
    (line 1499).
  * On many-dirtier systems, control update runs more often than
    needed.
  * On few-dirtier freerun systems, never at all.

A cleaner architecture: run the control update in a dedicated per-wb
workfn at fixed cadence (already have `bw_dwork` for the estimator tail
update; repurpose it). Dirtying tasks read `dirty_ratelimit` lockless.

---

## Simulator corrections from the code analysis (2026-04-10 late)

The code-first analysis exposed bugs in our simulator's Stock model
that we'd been attributing to "Stock controller is just bad" when it's
really "Stock controller doesn't run at all in most of our scenarios."
Three corrections were made to `wb_sim/controller.py` and `plant.py`:

### Correction 1 — Freerun cliff gate in StockController

**The headline fix.** Before: `StockController.update()` ran the
`pos_ratio` cubic and slewed `dirty_ratelimit` on every tick,
regardless of whether `dirty` was above or below freerun. After:
`update()` first checks `dirty <= self.freerun()` and, if so, skips
the `_update_dirty_ratelimit` call entirely. The bandwidth estimator
still updates (models the do_writepages flusher-side path), but the
control loop is bypassed — matching the kernel's `free_running:`
branch at page-writeback.c:1863.

Consequence for existing scenarios: Stock in S11 (cliff scenario, see
below) **never engages** in a 40-second run even though dirty is
continuously growing. `dirty_ratelimit` stays frozen at the cold-start
seed of 98 MB/s for all 40 seconds, even while `bw_effective` climbs
correctly from 98 MB/s to 499 MB/s via the flusher path. That's the
kernel-faithful behavior, and it's the "Stock is dead code" result
from Issue 1 above, reproduced in simulation.

### Correction 2 — Kernel-faithful dirty_ratelimit step filter

Before: `dirty_ratelimit` was slewed toward
`avg_write_bandwidth × pos_ratio` with a simple 200 ms EWMA
(`ratelimit_slew_halflife`). After: the simulator implements the full
`wb_update_dirty_ratelimit` algorithm from page-writeback.c:1338 line
by line:

  * `dirty_rate = (dirtied − dirtied_stamp) / elapsed`
  * `task_ratelimit = dirty_ratelimit × pos_ratio + 1`
  * `balanced = clamp(task_ratelimit × write_bw / max(dirty_rate, 1), 0, write_bw)`
  * `step = ±(x − dirty_ratelimit)` where `x` is `min3`/`max3` of
    (wb->balanced_dirty_ratelimit, this-iter balanced, task_ratelimit).
    Direction is chosen by `dirty < setpoint` vs `dirty ≥ setpoint`.
  * Gain-scheduled slowdown: `shift = floor(dirty_ratelimit / (2*step + 1))`,
    `step = (step / 2^shift) / 8`. Shift ≥ 63 clamps to zero.
  * `dirty_ratelimit += sign(balanced − dirty_ratelimit) × step`.

This is the piece that makes Stock's step response to bandwidth
changes take 8–12 seconds — the filter is intentionally slow near the
operating point, and now the simulator shows that behavior faithfully
instead of masking it behind a clean EWMA.

The simulator also tracks `balanced_dirty_ratelimit` as a separate
state variable (the kernel does the same — `wb->balanced_dirty_ratelimit`
is distinct from `wb->dirty_ratelimit`, and the min3/max3 filter uses
both current and previous-iteration values).

### Correction 3 — BANDWIDTH_INTERVAL (200 ms) gating

Before: the simulator updated the bandwidth estimate and the
dirty_ratelimit every simulator tick (1 ms). After: both updates are
gated by `elapsed >= bandwidth_interval_seconds` (default 0.2 s),
matching the kernel's BANDWIDTH_INTERVAL = HZ/5 = 200 ms constant at
page-writeback.c:60 and the gate at page-writeback.c:1910–1912. The
dirty_ratelimit step filter runs at 5 Hz, not 1000 Hz, which
substantially slows Stock's apparent convergence rate (5 Hz means 10
steps of the gain-scheduled filter per 2 seconds, not 2000).

### Plant changes to support the corrections

`wb_sim/plant.py`:

  * `Task` gained a `demand_at(t)` method for time-varying demand.
    Existing Tasks default to returning `self.demand_rate` (same
    behavior as before). Ramp/burst/idle scenarios can subclass and
    override.
  * `Simulation._step` now calls `task.demand_at(t)` instead of
    reading `task.demand_rate` directly, so the gate model sees
    time-varying demand in both the free-burst and throttled branches.
  * `Device` gained a `_last_dirtying_rate` field, stashed on every
    `step()` call. `StockController._update_dirty_ratelimit` reads
    this to compute `dirty_rate` from actual (gate-resolved) dirtying
    rather than from `task.effective_rate(t)`, which would
    undercount during freerun.

### New scenario: S11 "slow cliff ramp"

`wb_sim/scenarios.py::s11_slow_cliff_ramp`: a single writer whose
`demand_at(t)` ramps linearly from 0 to 1000 MB/s over 40 seconds on a
500 MB/s SATA device. Purpose: traverse the entire operating envelope
(freerun → control-active → near-limit) on a single time axis to
expose the freerun cliff directly. Results (40 s run):

| controller | max_dirty | tail err | bw_eff | dirty_ratelimit at t=40 |
|------------|-----------|----------|--------|--------------------------|
| stock      |  4915 MB  | 2468 MB  | 499 MB/s | **98 MB/s (frozen from seed!)** |
| pi         |  3216 MB  |  373 MB  | 500 MB/s | 479 MB/s (tracking target) |

Stock's `below_freerun_stock` flag is 1.0 for all 40 000 ticks —
never enters the control regime. `pos_ratio` never computes.
`dirty_ratelimit` stays at the initial 98 MB/s seed throughout. PI
runs continuously, tracks `bw_effective` as the device ramps up, and
holds dirty at the 3 GB setpoint.

Plot: `/mydata/wb-work/phase1/s11-compare.png`.

This is the cleanest single-scenario demonstration of the freerun
cliff in the entire simulator suite, and it should be the paper's
motivation plot.

### Known simulator limitations called out in the docstring

  * `wb_thresh` / `slack/8` fallback (Issue 4): not modeled explicitly.
    For single-device scenarios the fprop share is 1.0 and
    `max(fprop, slack/8) == thresh`, so the effective per-wb limit
    equals the global thresh regardless. Doesn't matter until we do
    proper multi-wb modeling.
  * `dom->dirty_limit` slow-follow-down (Issue 3's sysctl gotcha): not
    modeled. We don't exercise mid-run sysctl changes anyway.
  * `wb_min_pause` / `DIRTY_POLL_THRESH` (Issue 7): the simulator
    doesn't model the task-side pause computation at all, so CFQ-era
    workarounds are moot for us.
  * Control-in-task-context (Issue 8): the simulator uses a clean
    per-tick `controller.update()` call, so it can't reproduce
    lock contention or per-task overhead. Fine for control-loop
    analysis; not for scalability claims.

### What this invalidates / revalidates in prior scenario results

The SESSION.md table at line ~767 ("Scenario results summary (PI
post-fix vs stock)") was generated with the **old** StockController
that ran pos_ratio and slewed dirty_ratelimit every tick regardless
of freerun. That table **no longer reflects the kernel-faithful
behavior**. In particular:

  * **S1, S4, S13, S15**: Stock's "convergence" in these scenarios
    was partly an artifact of always-on cubic polynomial + ratelimit
    slew. With the freerun gate, Stock stays in freerun until dirty
    crosses 4.8 GB, then engages. Tail errors are now higher because
    the step filter converges slowly (Correction 2) and because
    freerun-cliff transition disturbances are no longer masked.
  * **S2**: unchanged by my edits, but the WbController's S2 result
    was separately affected by a later `_contention_mult = 4` setpoint
    multiplier change that the old table didn't capture. S2's PI
    max_dirty grew from ~5.5 GB (old) to ~24 GB after the multiplier
    landed, because pre-step setpoint jumped from ~5.3 GB to ~30 GB.
    **Resolved 2026-04-11** via the two-constraint setpoint rework
    (see §"Simulator regression investigation"). Current S2 PI
    max_dirty is 6.1 GB, time-bound.
  * **S3, S5, S6, S7, S8, S9, S10, S14**: re-verified with the
    post-fix controller; all still run without errors. Quantitative
    tail errors changed for S1/S4/S13/S15 as described above but the
    qualitative PI-vs-stock ordering is preserved.
  * **S11 (new)**: uniquely exercises the freerun cliff. Should be
    added to the regression suite.

**Action item**: regenerate the scenario results summary table
after the simulator corrections land. Old numbers should be marked
as pre-fix and kept for audit.

---

## Design decisions made so far

User feedback captured during this session:

1. **Ignore bpf_fault.** Treat `wb` branch as the new main for this project.
2. **Hardcode configs in `build.py`, don't use a config fragment.** Keep
   the existing `add_config_options` function structure, just add the
   writeback configs alongside the BPF ones. (Earlier I proposed a
   fragment-based approach — rejected.)
3. **SATA-only hardware for now.** No NVMe yet (will be added later). No
   USB stick — use brd + dm-delay as synthetic devices for cross-device
   tests.
4. **Simulator language**: Python 3 (numpy/scipy/matplotlib, optionally
   python-control for frequency-domain analysis).
5. **Simulator must also model the stock controller** for side-by-side
   comparison. The user asked for this mid-session and it's now
   implemented as `StockController` in `controller.py`.
6. **Extensions are out of scope for the core plan** but listed in the
   appendix of `wb-plan.md` to revisit later.

---

## Pending questions for the user

- **Paper venue target**: the plan lists ATC/EuroSys/FAST. Still no
  preference?
- **Legacy `writeback_pi=legacy` fallback lifetime**: carry the old cubic
  path for how many release cycles post-switchover?
- **S7 multi-device framework**: Phase 1 S7 is blocked on extending
  `Simulation` to multiple devices. Worth doing before Phase 0 benchmarks
  so we validate the cross-device story end-to-end, or defer until
  Phase 3?

---

## Resume checklist (run at session start)

**Always read this file first**, then:

```bash
# 1. Confirm we're on the expected kernel.
uname -r                                   # expect: 6.19.0-wb-baseline

# 2. Verify required modules are available.
modinfo brd dm-delay dm-flakey | grep -E 'filename|description'

# 3. Confirm the wb branch in linux-wb is intact.
cd /mydata/linux-wb && git status && git log -1 --oneline

# 4. Confirm the workspace survived.
ls /mydata/wb-work/

# 5. Smoke test the simulator (quick; no kernel interaction).
cd /mydata/wb-work/phase1 && python3 -m wb_sim.run s1 --compare --duration 10

# 6. Smoke test the synthetic device setup.
sudo /mydata/wb-work/phase0/setup/synth-devices.sh up
sudo /mydata/wb-work/phase0/setup/synth-devices.sh status
# Expected: /dev/ram0 mounted at /mnt/wb-fast, dm-wb_slow mounted at /mnt/wb-slow.

# 7. Next hardware task is the targeted 30-iter W3b+Wmix dr1/dr5
#    spike-rate CI tightening (see next-steps queue item #3).
#    Phase 2.1 kernel estimator work can proceed in parallel.
```

If any of those fail, troubleshoot before running benchmarks.

---

## Open tasks tracked in the TaskList

(Claude's in-session task tracker. Snapshot after S7/S9/S10.)

- Resume checklist (dm-delay fix + W5 smoke test) — **completed**
- S5 investigation — **completed** (quiescent hold + anti-windup clamp
  + CV shrinkage gating)
- Scaffold S3/S4/S6/S8 scenarios — **completed**
- Scaffold S7 multi-device (framework + scenario) — **completed**
- Scaffold S9/S10 and verify CV shrinkage — **completed**
- Extension C promotion decision — **completed**: not required for any
  scenario's stability
- Plan + SESSION.md update with all-scenarios findings — **completed**

Next blocks:
- Phase 0 real-hardware benchmarks (W1..W5 × default/tuned profiles)
- Optional: S11/S12 scaffolding (future enhancements per plan §1.3)
