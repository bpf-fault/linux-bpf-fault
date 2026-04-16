# Linux Writeback Redesign: Implementation and Evaluation Plan (v3)

> **Revision note (2026-04-11)**: v3 rolls back the "time-based per-wb
> limit replaces `dirty_ratio`" thesis from v2. Kernel validation showed
> the time-based setpoint throttles workloads that don't need to be
> throttled (a 200 MB buffered write on a 30 MB/s device with
> `drain_time = 2 s` ran at `bw_eff/4 ≈ 7.5 MB/s` — 5× slower than stock
> — because the 45 MB setpoint forced PI to throttle even though the
> user never asked for a sync-latency bound on this particular workload).
> `dirty_ratio`-based memory cap is restored as the primary throttle,
> and `drain_time_target` is redirected to drive background-flusher
> aggressiveness instead. See `SESSION.md` §"Design reframe (2026-04-11
> late)" for the full writeup.

## Summary

Replace Linux's dirty-page throttling — currently a per-bdi proportional share
of a global `dirty_ratio`, fed through a cubic position-ratio polynomial
(`wb_position_ratio()` → `pos_ratio_polynom()`) and a hand-rolled rate-limit
update (`wb_update_dirty_ratelimit()`) — with a control-theoretic design:

1. **Multi-timescale drain-rate estimator** replacing the single ~3-second EWMA
   in `wb_update_write_bandwidth()`.
2. **PI controller** replacing `wb_position_ratio()`'s cubic polynomial and
   `wb_update_dirty_ratelimit()`'s hand-rolled update. Always runs (no
   freerun cliff). One-sided error semantics and `bw_eff/4` output floor
   to break the estimator-controller feedback loop.
3. **Memory-based throttle setpoint** (kept from stock, not replaced):
   `setpoint = reserved_fraction × dirtyable_memory / num_active_wbs`
   with the existing `dirty_ratio` sysctl as `reserved_fraction`. PI
   engages at ~75 % of the setpoint and clamps at 100 %. The setpoint
   is RAM-proportional just like stock — the innovation is the
   *dynamics* (no cubic, no step filter, no freerun cliff), not the
   position.
4. **fprop replaced by equal-share `num_active_wbs` counter**. The
   stock fprop + slack/8 fallback produces a share that is effectively
   `slack/8` in the common case (see §"Kernel code analysis" in
   SESSION.md, Issue 4). Our replacement is: each currently-active wb
   gets `1/num_active_wbs` of the global budget, where "active" has a
   10 s hysteresis so bursty workloads don't churn the counter.
5. **Eager background flushing via `drain_time_target`**. Instead of
   being the task-throttle setpoint, `drain_time_target` drives
   `bg_thresh`: `bg_thresh_pages = drain_time × bw_eff` (minimum with
   stock's `dirty_background_ratio × dirtyable_memory`). The flusher
   wakes up earlier and drains during idle periods. The result: lower
   *observed* sync latency for interactive workloads that call `sync()`
   after short idle gaps, *without* throttling write() calls.

**Primary paper motivation**: Phase 0 hardware measurement
(see `SESSION.md` for the full sweep) found that
`dirty_ratio`/`dirty_background_ratio` tunables have **opposing optima
across workloads** on stock v6.19. On a 125 GB/SATA SSD test host:

- W3b (50 GB bulk + WAL fsync) at `dr1`: **12232× WAL p99.9 tail latency
  regression** vs default (173 ms p99.9 vs 14 µs baseline). Same
  workload at `dr20`: 4.5× ratio, no pathology.
- W4 (10 GB dirty + sync) at `dr1`: sync completes in 2.5 s (vs 23 s
  at `dr20`). Writer blocking time (`dirty_s`) at `dr1`: 20 s (vs 4.4 s
  at `dr40`).

The v3 pitch: **PI fixes the control *dynamics* at every `dirty_ratio`
point**. Stock's cubic + step filter is unstable at tight ratios (dr1),
which is why the WAL tail regresses 12232×. PI under the same
`dirty_ratio = 1` setting does not exhibit the step-filter collapse
because the integral-action has different numerical behavior. The
paper's evaluation: sweep `dirty_ratio ∈ {1, 5, 10, 20, 40}` on both
stock and PI and show that PI is stable at every point, while stock
has a pathological tail below `dr5`. This is a *dynamics* contribution,
not a *setpoint* contribution.

`drain_time_target` is a secondary knob that gives users who care
about sync-after-idle latency (interactive desktops, database
checkpointers) a way to trade flusher CPU for shorter drains. It does
**not** directly throttle writes.

**Goal**: publish a paper, then prepare an RFC patch series for linux-mm /
linux-fsdevel. No time deadline.

**Non-goals (explicitly deferred)**: priority-aware throttling, deadline-based
writeback scheduler, bandwidth probing, per-cgroup dirty tracking. These are
natural follow-ons but are out of scope for this plan — see the "Deferred
extensions" appendix at the end of this document for sketches to revisit
after the core lands.

**Base**: `wb` branch at pristine Linux 6.19. Work lands as a series of commits
on this branch, which becomes the RFC series.

**Target hardware**: SATA SSD as primary test device initially; NVMe added to
the Phase 3 evaluation matrix when it arrives. Multi-device cross-interference
tests use `brd` (ramdisk) as the fast side and `dm-delay` over a loop file as
the slow side (USB-stick proxy) — we do not have a real USB device.

**Target filesystem**: ext4 primary, XFS and btrfs for validation at 2.6.

**Simulator language**: Python 3 with numpy / scipy / matplotlib (plus
`python-control` if we want Bode or step-response analysis). Kernel code is C
per `Documentation/process/coding-style.rst`.

**Commit trailer convention** (from `Documentation/process/coding-assistants.rst`):
include `Assisted-by: Claude:claude-opus-4-6`. Do not add `Signed-off-by` (only
humans certify the DCO) and do not add `Co-Authored-By`.

Time estimates below are rough scoping ranges for a single kernel-experienced
developer working full-time, not commitments. Actual calendar time depends on
how many unknowns fall out of Phase 2.

---

## Upstream frictions to design around

Design constraints that shape the implementation before we write code. Each
was underestimated or wrong in the v1 plan.

- **Tracepoint ABI is stable.** The existing `writeback:balance_dirty_pages`
  tracepoint cannot have fields added or removed — userspace (perf-tools, bcc,
  bpftrace scripts) parses its format. New instrumentation lives in **new**
  tracepoints (`writeback:wb_bandwidth_multi`, `writeback:wb_pi_control`)
  emitted alongside the old one during parallel-run mode and as the canonical
  sources afterward. The old tracepoint stays intact.

- **PSI has no public "read current average" accessor.** `psi_group->avg[]` is
  internal. A small helper (e.g. `psi_mem_some_avg10()`) must be added as a
  prep patch in the RFC series. Fallback for `!CONFIG_PSI`: free+reclaimable
  ratio.

- **`task_struct` growth is resisted.** Any per-task state we need goes in a
  dynamically-allocated side structure, not new fields on `task_struct`. For
  the core plan we avoid per-task state entirely.

- **`struct super_operations` additions need two or three in-tree users and
  maintainer buy-in.** The core plan adds no filesystem callbacks; any such
  hook is deferred to a later extensions paper.

- **Flusher threads already do not call `balance_dirty_pages`.** They reach
  writeback via `wb_workfn → wb_writeback → __writeback_inodes_wb`, which does
  not throttle. The existing `PF_LOCAL_THROTTLE` path (used by loop devices)
  covers the reentrancy case. No new bypass logic is needed — verified against
  current source.

- **`writeback_chunk_size()` in `fs/fs-writeback.c:1895` already uses
  `wb->avg_write_bandwidth / 2`.** There is no fixed `MAX_WRITEBACK_PAGES`
  in the writeback path to replace. Phase 2.4 is a small swap of the input
  estimator and new clamps, not a chunking rewrite.

- **Function names post-BDI-split use the `wb_` prefix**, not `bdi_*`:
  `wb_position_ratio`, `wb_update_dirty_ratelimit`, `__wb_update_bandwidth`,
  `wb_dirty_limits`.

---

## Phase 0 — Baseline Characterization (~2 weeks)

Establish that the current writeback design has measurable pathologies on
modern hardware, with **pre-registered quantitative thresholds** for "pathology
confirmed". If a threshold is not met, the workload is dropped from the
motivation rather than reinterpreted.

### 0.1 Environment

- Test host, ≥32 GB RAM, SATA SSD as the real device.
- **Fast synthetic device**: `brd` (kernel ramdisk) formatted ext4. Appears as
  a regular block device to writeback but is memory-backed, so it stands in
  for a very fast real device.
- **Slow synthetic device**: loop file on the SATA disk + `dm-delay` with
  ~100 ms per-bio latency, yielding ~10 MB/s effective bandwidth as a
  USB-stick proxy.
- Kernel v6.19 (current `wb` branch) with `CONFIG_FTRACE=y`, `CONFIG_BPF=y`,
  `CONFIG_PSI=y`, `CONFIG_BLK_WBT=y`, `CONFIG_BLK_DEV_RAM=m`,
  `CONFIG_DM_DELAY=m`.
- Tools: fio, bpftrace, perf, blktrace, sysbench, stress-ng, Python analysis
  environment.

Record full inventory: `lsblk`, `cat /proc/meminfo`, `uname -a`, default
sysctls, `cat /sys/class/bdi/*/*`. Save per workload.

**When NVMe hardware arrives**, rerun Phase 0 on NVMe before Phase 3
evaluation. The v1 plan targeted NVMe primarily; SATA makes the pathologies
*more* visible (lower bandwidth → longer drain → `dirty_ratio × RAM` becomes a
larger absolute sync time), so SATA-first is actually a stronger motivation
story, not a weaker one.

### 0.2 Workloads with pre-registered thresholds

Each workload is run both with default sysctls and with manually tuned
sysctls. Pathology is confirmed only if the threshold is met; otherwise the
workload is dropped.

**W1 — Cross-device interference** (fast: brd+ext4, slow: dm-delay+ext4)
- Background: `dd if=/dev/zero of=/mnt/slow/bigfile bs=1M count=1024`
- Foreground: `fio --name=fast_lat --filename=/mnt/fast/testfile --rw=randwrite --bs=4k --size=100M --ioengine=libaio --direct=0 --runtime=120 --time_based --group_reporting`
- **Threshold**: fast-device p99 latency during slow-device write ≥ 3× the
  slow-idle baseline. If < 3×, pathology not demonstrated.
- Tuned comparison: `vm.dirty_bytes=50000000`,
  `vm.dirty_background_bytes=25000000`.

**W2 — Spiky throughput** (bandwidth estimator collapse)
- Loop 20 iterations: write 200 MB burst, sleep 3 s, delete, repeat. Record
  per-iteration throughput.
- **Threshold**: iteration-20 throughput ≤ 70% of iteration-1 throughput.
  Capture `wb->avg_write_bandwidth` via tracepoint across iterations to
  visualize estimate decay.

**W3 — Co-located latency + bulk** (WAL pattern + bulk writer on SATA)
- `fio` WAL: `--bs=8k --fsync=1 --ioengine=sync --runtime=120 --time_based`.
- Start bulk writer midway: `fio --bs=1M --ioengine=libaio --direct=0
  --size=50G --time_based --runtime=120`.
- **Threshold**: WAL p99.9 latency increases ≥ 10× when the bulk writer is
  active, versus WAL-only baseline.
- Tuned comparison: `vm.dirty_ratio=5`.

**W4 — Large sync latency**
- `dd if=/dev/zero of=/mnt/sata/bigfile bs=1M count=10240`, then `time sync`.
- **Threshold**: sync wall time ≥ 1.5× the naive bound
  `10 GB / measured_device_bandwidth`. On SATA at ~500 MB/s the naive bound is
  ~20 s; pathology if sync takes > 30 s. The excess captures scheduling
  inefficiency beyond raw drain.

**W5 — Sustained sequential baseline** (regression anchor, not a pathology claim)
- `fio --rw=write --bs=1M --size=50G --ioengine=libaio --direct=0 --time_based
  --runtime=120`.
- Record sustained bandwidth, latency distribution, `wb` state snapshots. This
  is the number Phase 3's prototype **must not regress by more than 5%**.

### 0.3 Instrumentation

- `perf record -e writeback:balance_dirty_pages -a` for every workload
- bpftrace: pause duration, `task_ratelimit`, `dirty_ratelimit`, `nr_dirty`,
  `wb_dirty`, `avg_write_bandwidth`, `pos_ratio`, per `balance_dirty_pages()`
  call
- `/proc/vmstat` sampled at 100 ms
- `iostat -x 1` device metrics
- `/proc/pressure/{memory,io}` PSI traces
- `blktrace` only where the pathology is ambiguous from higher-level metrics
  (high overhead)

### 0.4 Deliverables

- Per-workload time-series plots (dirty/writeback pages, throttle pauses,
  bandwidth estimate)
- Latency CDFs (default vs tuned)
- Pathology-confirmation table: workload × threshold × observed × confirmed
- Annotated trace excerpts for the paper's motivation section

---

## Phase 1 — Userspace Simulator (~2 weeks)

Validate the controller design before writing kernel code. Python 3,
discrete-time, 1 ms tick. Catch instabilities cheaply.

### 1.1 Plant model

State per simulated device: `dirty_pages`, `writeback_pages`.

```
dirty_pages     += dirtying_rate * dt
submitted        = min(dirty_pages, flusher_rate * dt)
dirty_pages     -= submitted
writeback_pages += submitted
completed        = min(writeback_pages, device_bandwidth * dt)
writeback_pages -= completed
```

`device_bandwidth` is time-varying (injectable GC events, spikes, step
changes). `flusher_rate` similarly. Multiple devices run independently in
the same simulation for multi-device scenarios via `MultiDeviceSimulation`.

**Task throttling mode (gate vs continuous)**. Two modes, selected per
`Simulation`:

- **`continuous` (legacy)**: each tick, `dirtying_rate = min(demand,
  task_ratelimit)`. This is simple but doesn't match the real kernel,
  which only throttles via `balance_dirty_pages` pauses when dirty
  exceeds `freerun`. Tasks below freerun dirty at memory speed.
- **`gate` (new, default)**: if `dirty_pages < controller.freerun()`,
  tasks dirty at full `demand_rate` (no throttling); above freerun,
  tasks are throttled at `task_ratelimit` as in continuous mode. The
  per-tick latency proxy `per_page_pause_s = 1 / task_ratelimit` is
  recorded for each throttled tick as a tail-latency indicator.

The gate model is what makes W3b-style BDP latency pathologies
visible in the simulator (without it, the simulator always throttles
and never reproduces the "below freerun, bursts absorb freely"
dynamic). Controllers must expose a `freerun()` method:
`StockController.freerun() = (thresh + bg_thresh) / 2` (matches
`dirty_freerun_ceiling`), `WbController.freerun() = 0.5 ×
sustained_limit`. Both controllers are always simulated in the same
mode for a given scenario, so stock vs PI comparisons are
apples-to-apples.

**Known simulator limitations** (documented so the paper's claims
are defensible):

1. **Deterministic symmetric plant** doesn't produce the rare
   transient overshoots that cause the hardware W3b 12232× p99.9
   pathology. The simulator reaches a smooth steady state; the
   hardware tail latency comes from the stochastic pause-cliff
   interaction during multi-task contention. Simulator reports
   per-page pause in the 17–80 µs range even on stress scenarios
   (S14 tight dr), not the ms-scale tails hardware shows.
   **Hardware W3b/Wmix is the primary source of tail-latency data
   in the paper; the simulator contributes the mean/median pause
   and the dirty-bound comparison.**

2. **StockController is a Python port, not the live kernel.** As
   of this revision it has the `wb_bandwidth_estimate_start()`
   quiescent hold and the correct period-weighted
   `wb_update_write_bandwidth()` formula, so it matches the
   v6.19 behavior line-by-line. Earlier versions missed the
   quiescent hold and exhibited an artifact "S5 collapse" that
   real v6.19 does not; that finding has been retracted in
   SESSION.md.

### 1.2 Controller (v3, 2026-04-11 reframe)

- **Three-timescale drain-rate estimator**: EWMAs over
  `WB_DIRTIED - WB_WRITTEN` deltas at ~700 ms, 2 s, 30 s half-lives.
  Fast-timescale period must be greater than `BANDWIDTH_INTERVAL`
  (200 ms), otherwise the `elapsed >= period` refresh branch fires on
  every sample and the "fast" EWMA collapses to zero on any idle tick.
  (Kernel validation 2026-04-11: set `WB_BW_FAST_PERIOD_TARGET = HZ +
  1` → roundup to 1024 jiffies on HZ=1000. Target half-life becomes
  ~710 ms, which is still "fast" relative to bw_medium's 2.8 s — the
  decoupled estimator workfn in the 2.1 follow-up can drop this back
  toward 50 ms.)
- `bw_effective = min(bw_fast, bw_medium)`, shrunk when CV > 0.5 **on a
  settled estimator**. "Settled" means
  `|bw_fast - bw_medium| < 0.25 × bw_medium` (fast and medium agree
  within 25 %). During the pre-settled transient (cold start, or after a
  large bandwidth step), shrinkage is suppressed — otherwise the 30 s
  EWMA's lag behind legitimate convergence shows up as false "noise" and
  pins `bw_eff` at the 0.2× floor (see S4 cold-start failure mode
  discovered in Phase 1 simulator). CV-shrinkage in the kernel
  implementation is still optional for now — the paper's headline
  scenarios don't need it.
- **Quiescent hold**: when `sample_rate_scaled == 0` (no writes in the
  last sample interval) AND `!wb_has_dirty_io(wb)` (no queued dirty
  I/O), skip the EWMA update entirely. Without this, idle intervals
  drag the EWMAs toward zero, which then drives the PI setpoint down
  and stalls any subsequent burst. The kernel port originally missed
  this and ate a full task freeze on the 200 MB buffered write; the
  fix is in commit "writeback: break PI estimator-controller feedback
  loop" on branch `wb`.
- Cold-start: unconfirmed flag with transport-type default, confirmed
  on first real writeback completion. Initial EWMA seed is INIT_BW =
  100 MB/s (same as stock).
- **Memory-based throttle setpoint** (v3):
  ```
  setpoint = reserved_fraction × dirtyable_memory / num_active_wbs
  ```
  Uses the existing `dirty_ratio` sysctl as `reserved_fraction`
  (default 20 %). This is **stock's setpoint shape** — the memory-
  proportional form is not an innovation. The innovation is the PI
  controller driving dirty to this setpoint, replacing stock's
  cubic `pos_ratio` and `wb_update_dirty_ratelimit` step filter.
  See §"Design reframe" in SESSION.md for the v2 → v3 rollback of
  the time-based setpoint.
- **Throttle engagement**: task is fully unthrottled when
  `dirty < setpoint × 0.75`. PI engages in the band
  `[setpoint × 0.75, setpoint]`. Above `setpoint`, PI drives the
  task rate hard and the output is floored at `bw_eff / 4` so the
  controller cannot stall a task indefinitely (the `bw_eff/4` floor
  breaks the estimator-controller feedback loop that was producing
  4 MB/s task rates on a 30 MB/s device in the 200 MB buffered test).
- **PI controller** with fixed nominal `Kp = 2`, `Ki = 1/(4 ×
  drain_time)`. Integral clamped to `±bw_eff` for anti-windup.
  One-sided error (`error = min(0, setpoint - dirty)`) so the
  controller never pushes ratelimit *up* below setpoint — only
  throttles from above.
- **`drain_time_target`** is repurposed in v3: it no longer drives
  the setpoint. Instead it controls the background flusher:
  ```
  bg_thresh = min(drain_time × bw_eff, dirty_background_ratio × dirtyable_memory)
  ```
  Smaller `drain_time` means the flusher starts writing at a smaller
  dirty pool, so idle periods are used productively to drain. The
  effect: observed sync latency goes down for workloads that call
  `sync()` after short idle gaps, **without** taxing writes with
  additional throttling. `drain_time` also scales `Ki` in the PI
  controller — smaller `drain_time` → larger `Ki` → faster integral
  action on the throttle side.
- **`num_active_wbs` equal-share replaces `fprop`**. Stock's
  `__wb_calc_thresh` uses floating-proportions to compute a
  bandwidth-weighted per-wb share of `thresh`, with a `slack/8`
  fallback that — as the code-first analysis showed (SESSION.md
  §"Kernel code analysis", Issue 4) — clobbers the fprop share in
  the common case. v3 deletes all of this and replaces it with
  `wb_share = setpoint / num_active_wbs`, where `num_active_wbs`
  is a per-`wb_domain` atomic counter with 10 s hysteresis on the
  transition edges. ~200 LOC deletion.
- **No `_contention_mult`**. The v2 single-writer 4× multiplier was
  retired — the memory-based setpoint is already large enough on
  typical systems that burst absorption for single writers happens
  naturally.
- **No freerun cliff**. Stock's `free_running:` branch in
  `balance_dirty_pages` (page-writeback.c:1863) is suppressed under
  `wb_use_pi = 1`. The PI control loop always runs.
- Elastic burst: 30 s low-pass filter on `throttle_intensity` drives
  `burst_multiplier` (still governs the `burst_limit` used for the
  throttle-intensity scaling).

### 1.3 Scenarios (pre-registered stability criteria)

> **v3 note**: the scenarios below were designed against the
> v2 time-based setpoint. Several criteria use language like "converges
> to setpoint" where the v2 setpoint was `drain_time × bw × 0.75`. Under
> v3, the setpoint is memory-based (`dirty_ratio × dirtyable_memory /
> num_active_wbs`), so the expected setpoint values are much larger and
> several criteria need to be rewritten. Scenarios marked **[RERUN]**
> need fresh simulator results. The v2 numbers in SESSION.md are kept
> as audit history but are NOT the v3 expected results.

For each, plot dirty pages, all three bandwidth estimates, PI P/I terms,
`burst_multiplier`, `task_ratelimit`, pause durations. Stability bar: no
sustained oscillation, overshoot < 20%.

| # | Scenario | v3 criterion | Status |
|---|---|---|---|
| S1 | Single writer, constant bandwidth | Dirty grows toward `memory_setpoint × 0.75`; task runs at device rate at steady state | **[RERUN]** |
| S2 | Bandwidth step 5 GB/s → 500 MB/s (GC event) | No post-step overshoot above `memory_setpoint`; drain rate equals device bandwidth (physics-limited recovery: `max_dirty_at_step / new_bw` seconds) | **[RERUN]** — memory setpoint is much larger, scenario needs a longer runtime |
| S3 | Two writers appearing/disappearing | Smooth `num_active_wbs` transition (1→2→1); per-wb share updates within 10 s hysteresis | **[RERUN]** |
| S4 | Cold start | `bw_effective ≥ 50%` of true device bandwidth within 2 s; within 5% by 4× sample interval | OK |
| S5 | Spiky workload (500 ms burst every 5 s) | `bw_effective` converges to true device bandwidth; `max_dirty` stabilizes; no per-burst ratchet. v3 *improves* S5 vs v2 because the larger memory-based setpoint absorbs bursts without PI throttling them. | **[RERUN]** |
| S6 | Extreme slow device (1 MB/s) | PI stable at device rate; dirty bounded under memory setpoint | OK |
| S7 | Multi-device, different speeds | Slow device's `num_active_wbs` contribution does not depress fast device's per-wb share; equal-share sharing works end-to-end | **[RERUN]** |
| S8 | Gain sweep: `Kp`, `Ki` ±50% from nominal | Overdamped across envelope; tail tracking error < 100 MB | **[RERUN]** — gains may need re-tuning under memory-based setpoint |
| S9 | Flash-GC stutter: 500 MB/s with 50 MB/s for 200 ms every 2 s | `bw_medium` tracks time-average; `task_ratelimit` does not crash during drops; dirty bounded | OK |
| S10 | Bandwidth jitter: Gaussian noise σ/μ = 0.6 | CV shrinkage engages on a settled estimator; `bw_eff` stays > 0.5× true mean; dirty bounded | OK |
| S11 | Slow cliff ramp (linear demand ramp on 500 MB/s device) | Stock freezes at cold-start `dirty_ratelimit` (never enters control regime); PI tracks `bw_effective` smoothly. This is the freerun-cliff motivation plot. | **PI win unchanged — the cliff absence, not the setpoint, is the contribution here** |
| S13 | Bulk writer + latency-sensitive WAL task | v2: tight time-based setpoint bounded WAL's latency. v3: the setpoint is memory-based, larger, so WAL sees similar tail latencies as stock. **The v2 PI advantage on S13 does NOT survive v3.** | **[RERUN / likely retire]** |
| S14 | Bulk + WAL with stock configured `dirty_ratio = 0.02` | v2: PI beat stock-tight-dr. v3: PI under default `dirty_ratio` won't beat stock at its minimum — the scenarios are measuring different regimes. | **[RERUN / likely retire]** |
| S15 | RocksDB+YCSB analog (WAL + compaction + periodic flush) | v2: "PI fills the Pareto gap" — a single PI config beat stock across four `dirty_ratio` points. v3: this result was driven by the tight time-based setpoint. Under v3, PI's max_dirty matches stock's `dr=0.20` point. | **[RERUN / likely retire]** |
| S16 | Constraint-crossover bandwidth step (200→8000→200 MB/s) | v2: exercised the time↔memory min() transition. v3: there's no time-based bound, so the scenario is just a bandwidth step — redundant with S2. | **Retire** |

Future (not yet scaffolded — pencilled in for Phase 1 extension or the
paper's "additional stress tests" appendix):

| # | Scenario | Criterion | Why it matters |
|---|---|---|---|
| S11 | Long idle (60 s) → single burst | `bw_effective` after the idle equals the pre-idle value (quiescent hold correctness at long horizons); burst response identical to cold start + one burst | Verifies the quiescent hold does not have an undocumented timeout failure — the anti-windup fix assumes holding indefinitely is safe, but `bw_slow`'s 30 s half-life interacts oddly with idle periods much longer than that. S5 only tests ≤4.5 s idle gaps. |
| S12 | Many writers (10, 100) on one device | Aggregate dirtying rate stays within 10% of `bw_eff`; per-task ratelimit distribution is even; no oscillation from many small PI outputs summing | Relevant because real kernels see tens to hundreds of dirtying tasks on one bdi. The simulator currently evenly divides `ratelimit_total / num_active_tasks`, which may not scale to 100 tasks with independent error measurements — need to test. |

**S2 criterion revision note**: the v1 plan had "recovery within 4 s after
reversion." Phase 1 simulator runs show that post-step recovery is
device-limited: after a 10× bandwidth drop, `dirty_pages` drains at
`new_device_bw`, so recovery time is `dirty_at_step / new_bw`. A 4 s
cap is only achievable if `dirty_at_step < 4 × new_bw`, which requires
either a small pre-step dirty level or a near-identity step. The
controller's job is to stop the growth at t=0⁺ (the simulator confirms
`task_ratelimit → 0` within 200 ms of the step) and then track the new
setpoint once drain completes. The criterion now describes what the
controller actually controls, not what physics does.

**S5 criterion revision note**: the v1 "`bw_medium` does not collapse
below 50% of true rate" phrasing measured the symptom, not the fix.
With the quiescent hold + anti-windup reset, the post-fix criterion
is steady-state convergence to the true device bandwidth and per-burst
stability. Simulator runs show `bw_effective` converging to 495 MB/s on
a 500 MB/s device within 9 bursts and `max_dirty` stabilizing at 484 MB
by burst 17 and holding flat through burst 23.

### 1.4 Output

- Python package (`wb_sim/`) with simulator, scenarios, plots
- Validated nominal `Kp`, `Ki`, gain schedule
- Stability analysis (damping ratios at sample operating points; optional Bode
  plot via `python-control`)
- Figures for the paper's design section

---

## Phase 2 — Kernel Prototype (~8-12 weeks)

The hard part. All work lands on `wb` as a series of commits that will become
the RFC patch series. Each sub-phase produces at least one reviewable commit.

### 2.1 Multi-timescale drain-rate estimator (~1.5 weeks)

Touches `mm/page-writeback.c`, `include/linux/backing-dev-defs.h`.

- Add fields to `struct bdi_writeback`: `bw_fast`, `bw_medium`, `bw_slow`,
  `bw_variance`, `bw_confirmed`, `bw_settled`.
- In `__wb_update_bandwidth()` (`mm/page-writeback.c:1489`), update all three
  timescales from the `(dirtied - written)` delta. Keep the existing
  `wb->avg_write_bandwidth` update for now — it remains the input to the
  legacy controller during parallel-run mode.
- **Quiescent hold**: skip the EWMA update when
  `wb->dirty_pages == 0 && wb->writeback_pages == 0 && last_completed == 0`
  and no task is currently dirtying on this wb. Without this guard, idle
  gaps drive `bw_fast`/`bw_medium` toward zero via `sample == 0` samples,
  creating a positive-feedback ratchet that collapses the estimator
  (Phase 1 S5 finding). Implementation: track an "active" predicate by
  OR-ing `list_empty(&wb->b_dirty)` and in-flight wb counters;
  alternatively, skip the update if `(dirtied - written) == 0` for the
  last two ticks and the bdi has no dirty pages.
- **Variance baseline is `bw_medium`, not `bw_slow`.** The simulator's
  initial design used `(sample - bw_slow)²` as the variance input, but
  that couples variance to the 30 s EWMA's lag during cold start and
  generates false-positive "noise" during legitimate convergence. Use
  `(sample - bw_medium)²` instead.
- **CV shrinkage is gated on `bw_settled`.** Only apply
  `bw_eff *= max(0.2, 1.0 - 0.5·(cv - 0.5))` when
  `|bw_slow - bw_medium| < 0.25 × bw_medium` (the three timescales have
  agreed within 25%). During the pre-settled transient, the variance
  signal is dominated by convergence artifacts, not real device noise.
  Setting `bw_settled` clears only — it never unsets (once settled, we
  trust the confidence signal on any subsequent transient).
- Cold-start: seed all three EWMAs from transport-type defaults
  (`q->limits.rotational`, `q->limits.max_hw_sectors`); flip
  `bw_confirmed` on the first real writeback completion sample.
- Expose all estimates + variance + `bw_settled` via a new tracepoint
  `writeback:wb_bandwidth_multi` (the old `writeback:bdi_dirty_ratelimit` and
  `writeback:balance_dirty_pages` remain untouched).

**Validation**: replay Phase 0 workloads, compare new estimates vs
`avg_write_bandwidth`. The fast-timescale estimate must track bandwidth
changes ≥ 2× faster than `avg_write_bandwidth`; the medium-timescale estimate
must not collapse on W2; S5-style spiky workloads must converge to the
true device bandwidth and stay there across idle gaps.

### 2.2 Memory-based setpoint + `num_active_wbs` share (v3) (~2 weeks)

Modifies `__wb_calc_thresh()` (`mm/page-writeback.c:900`) and adds the
`num_active_wbs` tracking.

- Add `atomic_t ctl_nr_active_wbs` to `struct wb_domain`.
- Add `ctl_last_active`, `ctl_in_global`, `ctl_deactivate_work` to
  `struct bdi_writeback`. Transitions are serialized by `wb->list_lock`
  in mark/deactivate paths.
- Add `wb_ctl_mark_active_locked()` / `wb_ctl_schedule_deactivate_locked()`
  hooks called from `wb_io_lists_populated()` / `wb_io_lists_depopulated()`
  in `fs/fs-writeback.c`. 10 s hysteresis on the deactivate side so
  bursty workloads don't churn the counter.
- Replace `__wb_calc_thresh()`'s fprop + slack/8 math with
  `wb_share = setpoint / max(num_active_wbs, 1)`, floored at
  `WB_CTL_MIN_BYTES` (16 MB).
- Delete `fprop_local_percpu completions` from `struct bdi_writeback`
  and all the supporting fprop infrastructure in `mm/page-writeback.c`
  and `mm/backing-dev.c`. ~200 LOC removed.
- `setpoint` itself stays memory-based:
  `setpoint = dirty_ratio × dirtyable_memory` (existing computation).
  No change to what `dirty_ratio` means.

Status: landed as commit `writeback: track num_active_wbs per wb_domain
with hysteresis` on branch `wb` (2026-04-11). fprop deletion is a
follow-up commit, not yet pushed.

### 2.2b `drain_time_target` as bg_thresh driver (v3) (~1 week)

New sysctl `vm.wb_drain_time_ms` (default 2000 ms). Used for two
secondary-mechanism purposes:

- **Background flusher threshold**: compute
  `bg_thresh_pages = drain_time × bw_eff`. Take the min of this and
  the existing `dirty_background_ratio × dirtyable_memory`. The
  flusher starts draining at whichever is smaller. On slow-device-
  large-RAM systems, `drain_time × bw_eff` dominates (smaller), and
  the flusher runs much earlier than stock. During idle periods
  between write bursts and `sync()` calls, the flusher catches up
  more, leading to shorter observed sync latency.
- **PI Ki gain scaling**: `Ki = 1 / (4 × drain_time)`. Smaller
  drain_time → larger Ki → faster integral action when throttling
  does engage.

Note: `drain_time_target` does **not** drive the task-throttle
setpoint. That's the v2 → v3 rollback documented in §"Summary"
and SESSION.md §"Design reframe". The task-throttle setpoint is
memory-based (§2.2).

**Validation**: boot modified kernel, run Phase 0 workloads. Verify
no panics / OOM / deadlocks. Verify `bg_thresh` is smaller under v3
for slow-device-large-RAM configs, and that the flusher actually
wakes up earlier (via tracepoints in `wb_workfn`). Compare stock
vs v3 on workloads that call `sync()` after short idle periods —
expect the observed sync latency to be smaller under v3 even
though worst-case `dirty_ratio × RAM / drain_rate` is unchanged.

### 2.3 PI controller replacing the cubic polynomial (~2 weeks)

Adds PI state fields (`pi_integral`, `pi_dirty_ratelimit`) to
`struct bdi_writeback`.

- Implement `wb_pi_update(wb, bw_eff, setpoint, elapsed_jiffies)` with
  nominal `Kp = 2`, `Ki = 1/(4 × drain_time)`. All 9 points of the
  ±50% gain sweep (S8) must pass tail tracking error < 100 MB.
- **Anti-windup strategy**:
  - Reset integral to zero when the wb becomes quiescent (same predicate
    as the estimator quiescent hold in 2.1). Prevents cross-idle
    accumulation on spiky workloads.
  - Clamp integral each tick to `±bw_eff`.
  - **Output floor at `bw_eff / 4`**. Prevents the "task frozen at 1
    page/sec" pathology caused by the p_term + integral saturating
    negative. Without the floor, when dirty is much greater than
    setpoint, the controller floors the output and feeds back a
    near-zero drain rate into the estimator, collapsing bw_eff over
    time. With the floor, the worst-case task rate is 1/4 of device
    rate, and the estimator observes a reasonable drain rate so it
    doesn't collapse. (Discovered on kernel validation 2026-04-11;
    see commit "writeback: break PI estimator-controller feedback
    loop" on branch `wb`.)
  - **One-sided error semantics**: `error = min(0, setpoint - dirty)`.
    Below setpoint, the controller outputs `bw_eff` (no active
    driving toward setpoint). Above setpoint, error is negative and
    throttles via p + i. Prevents the controller from pushing the
    task *up* to setpoint when the workload naturally sits below.
- Add tracepoint `writeback:wb_pi_control` exporting P-term, I-term,
  `ctl_setpoint`, `ctl_memory_ceiling`, `ctl_bw_eff`, output ratelimit,
  and binding-constraint label.
- **Task throttle engagement**: in `balance_dirty_pages`, when
  `wb_use_pi` is set, task_ratelimit reads from `wb->pi_dirty_ratelimit`
  (not stock's `dirty_ratelimit × pos_ratio`). Task is unthrottled below
  `setpoint × 0.75`, PI engages between `setpoint × 0.75` and
  `setpoint`, and is fully saturated above.

**Runtime switch**: `vm.wb_use_pi` sysctl (default 0) selects legacy
vs PI. Lets hardware benchmarks A/B on the same boot without rebuilding
the kernel. Status: landed as commit `writeback: switch
balance_dirty_pages to PI ratelimit under wb_use_pi` on branch `wb`.

**Pause computation**: use the existing `wb_max_pause` /
`wb_min_pause` plumbing with the PI output substituted for
`dirty_ratelimit`. No new pause logic.

**Reentrancy**: no new bypass logic. Flusher threads do not call
`balance_dirty_pages` in normal operation. `PF_LOCAL_THROTTLE` (loop
devices) is the only edge case and is already handled by current code.

**Validation**: run A/B via `wb_use_pi` across all Phase 0 workloads.
PI output should match stock under `dirty_ratio = 20%` on workloads
that don't cross the throttle threshold. On workloads that do (W3b,
Wmix), PI should have tighter control dynamics without the cubic's
singular points.

### 2.4 Bandwidth-proportional chunk sizing (~0.5 week, concurrent with 2.3)

Modifies `writeback_chunk_size()` in `fs/fs-writeback.c:1895`.

Current code already uses `min(wb->avg_write_bandwidth / 2,
global_wb_domain.dirty_limit / DIRTY_SCOPE)` — roughly a 500 ms target. The
change is small:
- Swap input: `bw_effective` instead of `avg_write_bandwidth`.
- Change target interval: 100 ms (new `WB_CHUNK_INTERVAL_MS` constant) instead
  of the implicit 500 ms.
- Add clamps `[16, 16384]` pages (64 KB to 64 MB).
- Keep superblock grouping logic unchanged. Deadline scheduling is explicitly
  out of scope.

**Validation**: verify chunk sizes are reasonable across device speeds via the
new tracepoint. No fs errors on ext4 / XFS / btrfs smoke tests.

### 2.5 Observability (concurrent with 2.3 / 2.4)

- `/sys/class/bdi/<device>/writeback_stats` sysfs text file: bw estimates,
  dirty counts, limits, PI state, burst multiplier, throttle intensity, state
  label.
- New tracepoints added: `writeback:wb_bandwidth_multi`,
  `writeback:wb_pi_control`. Old `writeback:balance_dirty_pages` intact (no
  field changes).
- Simple Python monitoring script in `tools/writeback/` that polls
  `writeback_stats` at 1 Hz and renders a live dashboard. Used for development
  and paper figures.

### 2.6 Integration testing (~2 weeks, overlapping 2.3-2.5)

- Boot on the real test host, not just vng, and run every Phase 0 workload.
- Mount / unmount, fsync, sync, crash consistency (dm-flakey).
- Heavy memory pressure: memhog at 80% RAM concurrent with writing.
- Filesystem matrix: ext4, XFS, btrfs each pass their `xfstests` quick group.
- If NFS is available (even loopback), smoke-test the variable-bandwidth path
  — it's a good proxy for future wireless / thin-provisioned backends.

---

## Phase 3 — Evaluation (~4-6 weeks)

### 3.1 Matrix

**Configurations (seven — the sysctl sweep is a first-class dimension)**:

- **`stock-dr1`** — unmodified v6.19, `dirty_ratio=1`
- **`stock-dr5`** — unmodified v6.19, `dirty_ratio=5`
- **`stock-dr10`** — unmodified v6.19, `dirty_ratio=10`
- **`stock-dr20`** — unmodified v6.19, `dirty_ratio=20` (default)
- **`stock-dr40`** — unmodified v6.19, `dirty_ratio=40`
- **`stock-best`** — per-workload best of the above five (computed offline;
  the upper bound an expert sysadmin could achieve with manual tuning)
- **`prototype`** — modified kernel, `target_drain_seconds=auto`, zero
  manual configuration

The autotuning claim is that `prototype` matches `stock-best` across
workloads, without needing the sweep or per-workload tuning. The five
`stock-dr*` points are needed to show:

- **There is no single best `stock-dr*`**: `stock-best` is composed of
  different `dr` values for different workloads (confirmed by Phase 0
  dirty-ratio sweep — W2 prefers dr1 but W4 sync_s is 9× worse there).
- **`dr1` is a catastrophic trap** for mixed workloads: 12232× WAL p99.9
  regression on W3b vs default. A design goal is that `prototype` is
  never worse than `dr20` on *any* metric while matching `stock-best`.

**Seven workloads**:
1. W1 — Cross-device interference (SATA + dm-delay, SATA as fast side —
   original brd-as-fast variant is retired; ramdisk latency is below
   fio's measurement resolution). Metric: SATA-writer throughput
   retention under slow-device interference.
2. W2 — Spiky throughput (W2b 5 GB bursts on default; W2 200 MB bursts
   kept as a sanity check)
3. W3 — WAL + bulk co-location (W3b 50 GB bulk is primary; 10 GB
   original kept as a control)
4. W4 — Large sync latency
5. W5 — Sustained sequential (regression check)
6. Wmix — WAL + bulk + timed sync, same host. Measures the
   multi-metric tradeoff: WAL p99.9, bulk MB/s, sync wall time.
   Phase 0's `no single dirty_ratio wins` evidence.
7. **W6 — Multi-tenant containers**: 4 cgroup v2 containers, each with a fio
   writer (1 heavy, 3 light). Measure per-container latency/throughput;
   compute Jain's fairness index.
8. **W7 — Realistic mix**: simultaneous `git clone`, `tar xf`, and a sysbench
   sqlite OLTP run. Measure sqlite p99 latency throughout.

**Iterations**: ≥ 5 per (configuration, workload) pair. Each workload
reports median, p95 range, and full distribution for latency-sensitive
metrics. The Phase 0 dirty_ratio sweep (2026-04-09) used n=1 and
exposed variance — the Wmix dr5 result (100 ms WAL p999) turned out
to be a single-iteration tail artifact; real claims must be
median-of-5 at minimum.

**Device matrix**: SATA first. When NVMe hardware arrives, rerun every
`(configuration, workload)` pair on NVMe as a second device class and report
both in the paper. If NVMe arrives during Phase 2, do SATA Phase 3 first
anyway to preserve a clean "slow device" story.

### 3.2 Metrics per run

- Throughput: total bytes, sustained MB/s, IOPS
- Latency: p50, p95, p99, p99.9, max, full CDF for latency-sensitive workloads
- Throttle: total pause time, pause count, pause distribution
- Dirty dynamics: time series of nr_dirty/nr_writeback with limit overlaid
- Bandwidth estimate accuracy: estimate vs measured drain rate
- Sync latency (sync invoked at peak dirty)
- System: CPU util, PSI memory/io, context switches

### 3.3 Statistical rigor

- 5 repetitions per `(configuration, workload)` minimum
- Mean + 95% CI
- Between runs: `sync; echo 3 > /proc/sys/vm/drop_caches; sleep 10`
- Mann-Whitney U for pairwise significance
- Full CDFs in the paper for latency-sensitive workloads

### 3.4 Hypotheses (pre-registered)

- **H1** (cross-device): Prototype fast-device p99 during slow-device write
  within 2× of slow-idle baseline; Stock ≥ 10× baseline.
- **H2** (spiky): Prototype maintains ≥ 80% of iteration-1 throughput across
  20 iterations; Stock < 50%.
- **H3** (co-location): Prototype WAL p99.9 within 5× of WAL-only baseline;
  Stock ≥ 50×.
- **H4** (sync): Prototype sync time < 2× `target_drain_seconds`; Stock sync
  proportional to `dirty_ratio × RAM / bandwidth`.
- **H5** (regression): Prototype sustained throughput ≥ 95% of Stock.
- **H6** (fairness): Prototype Jain's index > 0.9; Stock may be < 0.5.
- **H7** (realistic mix): Prototype sqlite p99 within 20% of Tuned without any
  manual configuration.

### 3.5 Ablation

Disable components one at a time and rerun the affected workload subset:
- Single-EWMA estimator → W2 regression expected
- Fixed `burst_multiplier = 1` → W5 regression expected
- `memory_signal = 0` (no PSI) → degradation under memory pressure
- `wbt_headroom = 1.0` → read latency during writeback worsens
- Fixed gains (no schedule) → oscillation or slow convergence at extremes

### 3.6 Sensitivity

- Sweep `target_drain_seconds` from 0.5 s to 16 s. Plot throughput/latency
  vs drain time. Auto-default should be near-optimal; degradation graceful.
- Sweep `Kp` ∈ [0.5, 8.0] (nominal 2.0). No oscillation across the range.
- Sweep `Ki` ∈ [0.1, 2.0] × `1/drain_time` (nominal 0.5).

### 3.7 Figures

1. Motivation: W1 time series under Stock, annotated pathology
2. Design: block diagram (plant, PI, gain scheduler, sensors)
3. Simulator: S1/S2/S5 convergence plots
4. Eval: CDFs for W1, W3, W7 (three configs)
5. Eval: throughput bars for W2, W5 (three configs)
6. Eval: time series of dirty pages + drain rate for W2, Stock vs Prototype
7. Ablation bar chart
8. Sensitivity heatmap (throughput/latency vs `target_drain_seconds` and `Kp`)

---

## Phase 4 — Paper and Upstream RFC (~3-4 weeks, overlaps Phase 3)

### 4.1 Paper

Target venues: USENIX ATC, EuroSys, or FAST.

- Abstract, intro, background (writeback architecture brief + control theory
  primer for a systems audience)
- Motivation: Phase 0 results with quantitative thresholds
- Design: PI controller, gain scheduling, elastic burst, sensors, stability
  analysis
- Implementation: kernel changes, LoC, integration points, commit series
- Evaluation: Phase 3 results mapped to hypotheses
- Discussion: filesystem interaction, cgroup future work, blk-wbt coupling,
  explicitly-deferred extensions
- Related work: CoDel / AQM, cpufreq schedutil, thermal, Hellerstein et al.,
  Zhu et al.

### 4.2 Upstream RFC

Cover letter + patches, CC `linux-mm`, `linux-fsdevel`, Jan Kara, Tejun Heo,
Jens Axboe, Matthew Wilcox. Use `b4 prep` / `b4 send` via the `b4` skill.

Split (v3):
1. **Prep**: `psi_mem_some_avg10()` helper (linux-mm only; can go standalone)
2. **Prep**: `wbt_headroom()` accessor (block layer; standalone)
3. Multi-timescale bandwidth estimator + `writeback:wb_bandwidth_multi`
4. `num_active_wbs` counter + hysteresis (per-`wb_domain`)
5. `wb_ctl_*` setpoint/ceiling helpers (memory-based setpoint +
   num_active_wbs share; setup for fprop deletion)
6. PI controller (`wb_pi_update`) + `writeback:wb_pi_control`
7. Switchover: `balance_dirty_pages` consumes `pi_dirty_ratelimit`
   under `vm.wb_use_pi`. Default off.
8. Delete fprop + freerun cliff (behavior change gated on
   `wb_use_pi`; legacy path still reachable)
9. `vm.wb_drain_time_ms` sysctl wired to `bg_thresh`
10. Chunk-sizing swap in `writeback_chunk_size()`
11. Observability: `writeback_stats` sysfs file + `tools/writeback/` dashboard

Each patch stands alone with test results, before/after numbers, and a clear
changelog.

Present at LPC writeback/MM microconference or LSFMM if timing aligns. The
patch series lands independently of the paper.

---

## Risk mitigation

**PI instability in kernel**: Phase 1 simulator catches most of it. Phase 2.3
parallel-run mode validates against the existing polynomial before switchover.
Legacy path stays reachable via `writeback_pi=legacy` boot parameter through
the RFC review period.

**Filesystem-specific breakage**: test ext4 / XFS / btrfs early at Phase 2.6,
not deferred. The drain-rate estimator is fs-agnostic. Known problem cases
(journal-full stalls, CoW amplification) are mitigated by tighter dirty
limits, not prevented; acknowledge in the paper's discussion.

**No improvement over tuned sysctls**: the contribution is "as good as tuned,
without tuning". Equivalence is success. Cross-device and spiky-workload
improvements are the secondary contribution — no amount of tuning fixes those
in the current design.

**blk-wbt accessor rejected**: `wbt_headroom` is a sensor, not a hard
dependency. If rejected, wire it to 1.0 and document as future work. The
system degrades gracefully.

**PSI helper rejected or contested**: the helper is a trivial accessor and
likely acceptable. The `!CONFIG_PSI` fallback path is already in the design;
if the helper itself is rejected, keep the fallback for all configs.

**SATA-only baseline unconvincing**: SATA makes the pathologies *more* visible
than NVMe (longer drains, larger absolute `dirty_ratio × RAM` sync times), not
less. When NVMe arrives, rerun Phase 0 and confirm the same pathologies at
smaller absolute magnitudes — strengthens the paper rather than weakens it.

**Tracepoint churn**: all new tracepoints are additive. The old
`writeback:balance_dirty_pages` is never modified. No ABI break.

**PI controller deadlocks on an OOM path**: keep the simulator's stress
scenarios covered (S6 extreme slow device, S8 gain sweep) and add one kernel
test in Phase 2.6 running memhog at 95% RAM concurrently with sustained
writeback. If we see stalls there, integral reset logic needs tightening
before switchover.

---

## Tools and dependencies

**Software**: fio, bpftrace, perf, blktrace / blkparse, Python 3 + numpy /
scipy / matplotlib (+ optional `python-control`), sysbench, stress-ng,
dm-flakey (data integrity testing), vng / virtme-ng (dev-loop boot testing).

**Hardware currently available**: SATA SSD + ≥ 32 GB RAM. NVMe to be added
to the matrix on arrival.

**Kernel config fragment**: `CONFIG_FTRACE=y`, `CONFIG_BPF=y`, `CONFIG_PSI=y`,
`CONFIG_BLK_WBT=y`, `CONFIG_BLK_DEV_RAM=m`, `CONFIG_DM_DELAY=m`,
`CONFIG_DM_FLAKEY=m`, `CONFIG_CGROUP_WRITEBACK=y` (for W6), `CONFIG_MEMCG=y`
(for W6).

**Build**: plain `make LLVM=1 CC=clang -j$(nproc)` on the `wb` branch. A
writeback-specific config fragment can be added once it stabilises; not needed
for Phase 0-1. For dev-loop boot testing use the `virtme-ng` and
`build-and-boot` skills.

---

## Open questions before Phase 0 starts

1. **Test-host access model**: is Phase 0 bare-metal on this host, or do we
   need a separate dedicated machine? Reliable I/O benchmarks need exclusive
   access to the device under test.
2. **NVMe ETA**: rough timing? Determines whether Phase 3 runs SATA-first-then-
   NVMe (sequential, safer) or waits on NVMe.
3. **Parallel-run commit in upstream history**: keep it as an intermediate
   commit for reviewer context, or squash into the switchover? Leaning toward
   keep-it for the first posting, squash only if reviewers object.
4. **Legacy `writeback_pi=legacy` fallback lifetime**: one release cycle? Two?
   The design drops `wb_update_dirty_ratelimit()` entirely at switchover, so
   "legacy" reachable via boot param means carrying both code paths for a
   while. Decide before the RFC posting.
5. **`tools/writeback/` monitoring script**: ships in-tree with the series, or
   lives out-of-tree until the core lands? Either is fine; in-tree is a bit of
   extra review surface but gives downstream users something to look at.

---

## Appendix: Deferred extensions

Out of scope for this plan. Listed here so they're not lost — revisit after
the core lands upstream (or after the first paper is accepted). Each extension
assumes Phases 0-4 are complete; specific prerequisites are noted. Sketches
only — the full design work happens when we pick them up.

Recommended ordering if we pursue any of them: **A → C → B → D**. A is the
smallest and validates the priority framework. C is small and improves the
core estimator. B is medium-invasive but self-contained. D is the largest and
most risky.

Natural grouping for follow-on papers:
- **A + C** together: "completing the control loop" (priority differentiation
  + capacity probing).
- **B + D** together: "scheduling and isolation" (deadline scheduling +
  per-page cgroup attribution).

### Extension A — Priority-aware throttling

**Goal**: let latency-sensitive applications (databases, interactive tools)
be protected from throttling caused by co-located bulk writers, without
per-workload sysctl tuning.

**Prerequisite**: Phase 2 complete (PI controller functional).

**Sketch**:
- Three throttle classes derived from existing `IOPRIO_CLASS_*`:
  - **Latency-sensitive** (`IOPRIO_CLASS_RT`): max pause capped at 10 ms,
    throttle onset delayed to 0.9× `burst_limit`, rate-capped at
    `2 × bw_effective / num_rt_dirtiers`.
  - **Normal** (`IOPRIO_CLASS_BE`): unchanged from Phase 2.
  - **Bulk** (`IOPRIO_CLASS_IDLE`): throttle onset lowered to 0.5×
    `sustained_limit`, absorbs throttling first when
    `throttle_intensity > 0.1`.
- Implementation touches only `balance_dirty_pages()` — read `io_prio`,
  select `max_pause` and `throttle_onset` per class. The PI controller itself
  doesn't change; priority affects distribution of its output.
- Cgroup v2 integration is free: `io.prio.class` already exists.

**Abuse prevention**: track per-task sustained dirty rate over 10 s. If RT
class sustains > 20% of `bw_effective` for > 5 s, auto-downgrade to Normal
with `pr_warn_ratelimited`.

**Known upstream friction**:
- Per-task state (`sustained_dirty_rate`, `rt_downgrade_until`) cannot go on
  `task_struct`. Needs a side-table, likely hanging off the wb or a dynamically
  allocated blob reached via a hash keyed by `task->pid`. Or an existing
  `task_dirty_info`-style structure if someone else adds one first.
- The "`task_dirty_info` structure if one exists" phrase from v1 was wishful
  thinking — no such structure exists today. Solve the storage question before
  writing code.

**Workload**: rerun W3 with DB at `IOPRIO_CLASS_RT`, batch at
`IOPRIO_CLASS_IDLE`. Target: RT WAL p99.9 < 2 ms even under heavy bulk.
Hypothesis H8: RT classification reduces WAL p99.9 by > 5× vs unprioritized
prototype.

### Extension B — Deadline-based writeback scheduler

**Goal**: replace the periodic 5-second wakeup and fixed-chunk inode iteration
with an event-driven, deadline-ordered scheduler. Eliminate idle wakeups,
ensure timely writeback of aging dirty data, prioritize urgent writeback
across filesystems.

**Prerequisite**: Phase 2 complete (time-based limits + bandwidth-proportional
chunk sizing). This is the most invasive fs-writeback.c change in the
extension set.

**Sketch**:
- **Per-inode deadline**: `deadline = dirtied_when + max_dirty_age`, where
  `max_dirty_age = max(1 s, 2 × target_drain_seconds)`. Stored on `inode` or
  derived from `dirtied_when`.
- **Three scheduling tiers** processed in order:
  - Tier 0 (Expired): `deadline < jiffies`, oldest-first.
  - Tier 1 (Background): dirty pages > 0.5× `sustained_limit`,
    largest-dirty-inode-first.
  - Tier 2 (Routine): oldest-first default.
- Keep the existing `b_dirty` / `b_io` / `b_more_io` infrastructure; just
  change iteration order in `writeback_sb_inodes()` / `wb_writeback()`. Don't
  build a literal heap.
- Group by superblock within each tier to preserve filesystem locality.
- **Event-driven wakeup**: replace `delayed_work` timer with a dynamic timer.
  `next_deadline` field tracking earliest known deadline. On `__mark_inode_dirty()`,
  update `next_deadline` if newer inode's is earlier. When flusher finishes,
  recompute from `b_dirty` head. If no dirty inodes remain, cancel the wakeup
  entirely.
- **Deprecate `dirty_writeback_centisecs`** to a safety-net max-idle-interval
  (default 30 s instead of 5 s).
- **Power-management hook**: per-device `power_mode` sysfs selector adjusting
  `max_dirty_age` (`performance` / `balanced` / `powersave`).

**Known upstream friction**:
- Filesystem consistency must be maintained — journal ordering, locking
  assumptions. The v1 hand-wave "filesystem consistency is maintained within
  `->writepages()`, not by MM-layer inode ordering" is directionally right
  but needs per-filesystem review. XFS in particular has strong assumptions
  about the order of inode presentation.
- Extensive data integrity testing with dm-flakey and crash recovery.

**Workloads**: W9 (zero-dirty idle: 0 wakeups target vs ~12 stock), W10
(writeback timeliness: 1000 small files, verify < 4 s worst-case writeback
latency vs 35 s stock).

### Extension C — Bandwidth probe mechanism

**Goal**: break the positive feedback loop where the drain rate estimator
underestimates capacity because the dirty limit (derived from the estimate)
constrains how much writeback the flusher can do. Periodically probe for
spare capacity by temporarily inflating the dirty limit.

**Note on Phase 1 S5 finding**: during Phase 1 simulator work we initially
thought Extension C might be needed to fix S5's `bw_effective` collapse on
spiky workloads. It is not — the collapse was caused by two bugs inside
the estimator and PI (unguarded EWMA decay during idle gaps, and PI
integral windup across burst cycles), which are fixed by the
quiescent-hold + anti-windup design now baked into Phase 2.1 and 2.3.
Extension C addresses a *different* pathology: the long-run steady-state
fixed point where PI stabilizes slightly below true device capacity
because the estimator only sees what the controller lets the flusher
drive (S1 shows this as ~490/500 MB/s with the core design). That is a
convergence-accuracy question, not a stability question, and remains an
optional post-core improvement worth discussing in the paper.

**Prerequisite**: Phase 2 complete. Improves accuracy of Phase 2's estimator.

**Sketch**:
- **Probe interval**: every `10 × target_drain_seconds`, tracked per
  `bdi_writeback` in `next_probe_jiffies`.
- **Probe duration**: `target_drain_seconds`.
- **Probe action**: multiply `burst_limit` by 1.5 for the probe window.
- **Probe measurement**: compare drain rate during vs before. If +10%, revise
  `bw_effective` upward. If no change, confirm current estimate.
- **Probe cooldown**: after an unsuccessful probe, double the interval (cap
  5 minutes). Reset on success.
- **Suppression conditions**:
  - `throttle_intensity > 0.3`
  - `wbt_headroom < 0.5`
  - PSI memory-some > 10%
  - filesystem callback `sb_can_accept_more_dirty()` returns false
- **Interaction with elastic burst**: probe inflation is temporary and
  filtered out of the 30-second `throttle_intensity` EWMA.

**Known upstream friction**:
- `sb_can_accept_more_dirty()` is a new `struct super_operations` field.
  Upstream wants two or three in-tree users before accepting a new sop hook.
  Implement ext4 first (needs a new `jbd2_journal_check_available()` helper —
  does not currently exist, so this is itself a sub-project), and plan
  btrfs + XFS as follow-ups. Budget this as a 4-week subproject, not a week
  of work.
- Keep it optional: default return `true`, filesystem-specific overrides
  opt-in. Feature works without it (system degrades gracefully to
  "probe harder", which is fine in normal operation).

**Workload**: W11 (bandwidth convergence: artificially cap initial estimate
to 50% of device speed; target probe mechanism converges to >90% within
3 probe cycles).

### Extension D — Per-(cgroup, device) dirty tracking

**Goal**: replace per-inode cgroup writeback ownership (Boyer-Moore majority
vote with 2-second stabilization delay, `inode->i_wb_frn_*` fields) with
per-page cgroup attribution. Enables true per-container dirty isolation even
for shared files.

**Prerequisite**: Phase 2 + 3 complete. **This is the largest and riskiest
extension — strong candidate for a separate paper rather than a core
follow-on.**

**Sketch**:
- **Per-(memcg, wb) counters**: `struct wb_memcg_stats` per active
  (memcg, wb) pair, allocated lazily, stored in an xarray/hash keyed by memcg
  ID off `struct bdi_writeback`. Holds dirty count, writeback count, and
  per-cgroup PI controller state.
- **Hot-path accounting**: modify `folio_account_dirtied()` and friends to
  look up `folio->memcg_data` (already tracked by memcg) and update the
  `wb_memcg_stats` counters. This is ~every dirty/clean transition → a hash
  lookup on the hot path. Per-CPU batching amortizes the cost across ~32
  page transitions.
- **Per-cgroup dirty limits**:
  `cgroup_device_limit = sustained_limit × (memcg_io_weight / sum_active_weights)`.
  Each (memcg, wb) pair gets its own PI controller instance with the same
  gain schedule. `balance_dirty_pages()` checks both per-(memcg, wb) and
  device-level limits.
- **Eliminate Boyer-Moore**: retain inode-level `bdi_writeback` association
  as a *scheduling hint*, but replace the `i_wb_frn_*` vote machinery with a
  simpler "most recent dirtier's wb" association. Per-page attribution
  handles the accounting correctly regardless of which flusher processes the
  inode.
- **Filesystem support**: filesystems without `SB_I_CGROUPWB` still get
  correct per-cgroup accounting (throttling works per-cgroup), but writeback
  scheduling remains root-wb. Document this split in cgroup v2 docs.

**Known upstream friction**:
- Hot-path overhead is the biggest risk. Target: < 100 ns per dirty/clean
  transition (vs current ~50 ns for global counter update). Measure with
  `perf stat -e cycles` on the `balance_dirty_pages` path before upstreaming.
- RCU lifecycle for `wb_memcg_stats` needs care — memcgs can disappear, per-CPU
  batches can be in-flight, wb's can be destroyed. Garbage collection for
  idle cgroups after ~30 seconds.
- Memory overhead analysis: ~64 bytes per (memcg, wb) pair + ~8 bytes per
  per-CPU batch. 100 cgroups × 4 devices × 128 CPUs ≈ 400 KB. Acceptable but
  not free.
- Tejun Heo (memcg writeback maintainer) and Johannes Weiner (memcg
  maintainer) both need to be convinced. Start with a design discussion on
  linux-mm, not patches.

**Workload**: W12 (shared-file cgroup isolation: two cgroups mmap the same
10 GB file; target Jain's index > 0.95 vs < 0.7 with inode-level
attribution).

### Extension Evaluation — cumulative ablation

When extensions are added, run an incremental ablation matrix:

| Configuration | W3 (WAL p99.9) | W9 (wakeups) | W11 (BW convergence) | W12 (fairness) |
|---|---|---|---|---|
| Stock | baseline | baseline | baseline | baseline |
| Phase 2 (core prototype) | ✓ | same | ✓ | ✓ |
| + Ext A (priority) | ✓✓ | same | same | same |
| + Ext B (deadline) | same | zero | same | same |
| + Ext C (probe) | same | same | ✓✓ | same |
| + Ext D (cgroup) | same | same | same | ✓✓ |
| All extensions | best | zero | best | best |

Shows each extension addresses a distinct problem and benefits compose.
