// SPDX-License-Identifier: GPL-2.0-only
/*
 * bench_fault_overhead_baseline — baseline anonymous fault overhead breakdown.
 *
 * Dissects the per-fault latency of the kernel's anonymous fault path
 * into 4 sub-phases using BPF kprobes and userspace timestamps.
 *
 * Read mode (default): zero-page map — the cheapest anonymous fault,
 * the same operation that bpf_fault replaces.
 *
 * Write mode (-W): real page allocation — alloc_anon_folio, rmap,
 * LRU, set_ptes.  Shows the cost of actually backing a page.
 *
 * Timeline (both modes share the same probe points):
 *
 *   t0: access page -> FAULT
 *   HM:   handle_mm_fault entry
 *           [inlined: __handle_mm_fault: PGD/P4D/PUD/PMD walk]
 *           [inlined: handle_pte_fault]
 *   PM:     do_pte_missing entry
 *           [inlined: do_anonymous_page]
 *           Read:  pte_alloc, zero-page PFN, set_ptes
 *           Write: vmf_anon_prepare, alloc_anon_folio, rmap, set_ptes
 *   HR:   handle_mm_fault return
 *   t5: back to userspace
 *
 * With -k (4 sub-phases):
 *    1  Fault entry        (t0->HM)   arch fault handler dispatch
 *    2  Page table walk    (HM->PM)   PGD/P4D/PUD/PMD + PTE dispatch
 *    3  Page handling      (PM->HR)   mode-dependent (see above)
 *    4  Kernel->user       (HR->t5)   fault return to userspace
 *
 * Usage:
 *   ./bench_fault_overhead_baseline [-n pages] [-w warmup] [-r rounds]
 *                                   [-c cpu] [-k] [-W] [-C] [-o file]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "overhead_baseline_kprobe.skel.h"
#include "bench_fault_util.h"

#define NPHASES		4
#define NUM_PROBE_HITS	3	/* HM entry, PM entry, HM return */
#define CALIB_PAGES	1024	/* pages for probe overhead calibration */

/* Matches struct baseline_fault_ts in overhead_baseline_kprobe.bpf.c */
struct kernel_fault_ts {
	uint64_t t_hmf_entry;
	uint64_t t_hmf_return;
	uint64_t t_pte_missing;
};

struct fault_ts {
	uint64_t t_fault_start;		/* t0 */
	uint64_t t_fault_done;		/* t5 */
	uint64_t t_hmf_entry;		/* HM */
	uint64_t t_hmf_return;		/* HR */
	uint64_t t_pte_missing;		/* PM */
} __attribute__((aligned(128)));

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static inline int64_t clamp_pos(int64_t v) { return v > 0 ? v : 0; }

static inline int64_t phase_delta(uint64_t a, uint64_t b)
{
	if (!a || !b)
		return 0;
	return clamp_pos((int64_t)(a - b));
}

static void pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		fprintf(stderr, "  warning: pin to CPU %d failed: %s\n",
			cpu, strerror(errno));
}

static uint64_t calibrate_timer(void)
{
	const int N = 100000;
	uint64_t start, end;

	start = now_ns();
	for (int i = 0; i < N; i++)
		now_ns();
	end = now_ns();

	return (end - start) / N;
}

static int cmp_i64(const void *a, const void *b)
{
	int64_t va = *(const int64_t *)a;
	int64_t vb = *(const int64_t *)b;

	return (va > vb) - (va < vb);
}

struct phase_stat {
	int64_t avg;
	int64_t min;
	int64_t max;
	int64_t p50;
	int64_t p99;
	double pct;
};

static struct phase_stat compute_stat(int64_t *lat, size_t n,
				      int64_t total_avg)
{
	struct phase_stat s = { 0 };
	int64_t sum = 0;

	if (!n)
		return s;

	qsort(lat, n, sizeof(int64_t), cmp_i64);

	s.min = lat[0];
	s.max = lat[n - 1];
	for (size_t i = 0; i < n; i++)
		sum += lat[i];
	s.avg = sum / (int64_t)n;
	s.p50 = lat[n / 2];
	s.p99 = lat[(size_t)(n * 0.99)];
	s.pct = total_avg > 0 ? 100.0 * s.avg / total_avg : 0;

	return s;
}

/* ------------------------------------------------------------------ */
/*  Phase definitions                                                  */
/* ------------------------------------------------------------------ */

/* Phase 3 name depends on fault mode */
static const char *phase_names_read[NPHASES] = {
	"Fault entry        (t0->HM)",
	"Page table walk    (HM->PM)",
	"Zero-page map      (PM->HR)",
	"Kernel->user       (HR->t5)",
};

static const char *phase_names_write[NPHASES] = {
	"Fault entry        (t0->HM)",
	"Page table walk    (HM->PM)",
	"Page alloc + PTE   (PM->HR)",
	"Kernel->user       (HR->t5)",
};

static const char *phase_csv_read[NPHASES] = {
	"fault_entry", "page_table_walk",
	"zero_page_map", "kernel_to_user",
};

static const char *phase_csv_write[NPHASES] = {
	"fault_entry", "page_table_walk",
	"page_alloc_pte", "kernel_to_user",
};

static const char *phase_prefix[NPHASES] = {
	"  1", "  2", "  3", "  4",
};

/*
 * Probe boundary types for measurement overhead correction.
 *
 * Phase  Start     End
 *  0     t0(tmr)   HM(kp)       0    1
 *  1     HM(kp)    PM(kp)       1    1
 *  2     PM(kp)    HR(krp)      1    1
 *  3     HR(krp)   t5(tmr)      1    0
 */
static const int start_is_probe[NPHASES] = {
	0, 1, 1, 1
};
static const int end_is_probe[NPHASES] = {
	1, 1, 1, 0
};

/* ------------------------------------------------------------------ */
/*  BPF setup / readback                                               */
/* ------------------------------------------------------------------ */

static struct overhead_baseline_kprobe_bpf *bpf_setup(void *region,
						       size_t region_size)
{
	struct overhead_baseline_kprobe_bpf *skel;

	skel = overhead_baseline_kprobe_bpf__open();
	if (!skel) {
		fprintf(stderr, "  error: failed to open BPF skeleton\n");
		return NULL;
	}

	skel->rodata->target_tgid = getpid();

	if (overhead_baseline_kprobe_bpf__load(skel)) {
		fprintf(stderr, "  error: BPF load failed: %s\n",
			strerror(errno));
		overhead_baseline_kprobe_bpf__destroy(skel);
		return NULL;
	}

	skel->bss->region_start = (uint64_t)(unsigned long)region;
	skel->bss->region_end = (uint64_t)((unsigned long)region +
					    region_size);

	if (overhead_baseline_kprobe_bpf__attach(skel)) {
		fprintf(stderr, "  error: BPF attach failed: %s\n",
			strerror(errno));
		overhead_baseline_kprobe_bpf__destroy(skel);
		return NULL;
	}

	return skel;
}

static void bpf_read_timestamps(struct overhead_baseline_kprobe_bpf *skel,
				struct fault_ts *ts, void *region,
				size_t num_pages, size_t page_size)
{
	int map_fd = bpf_map__fd(skel->maps.kernel_ts);
	int found = 0, missing = 0;

	for (size_t i = 0; i < num_pages; i++) {
		uint64_t addr = (uint64_t)((unsigned long)region +
					   i * page_size);
		struct kernel_fault_ts kts;

		if (bpf_map_lookup_elem(map_fd, &addr, &kts) == 0) {
			ts[i].t_hmf_entry   = kts.t_hmf_entry;
			ts[i].t_hmf_return  = kts.t_hmf_return;
			ts[i].t_pte_missing = kts.t_pte_missing;
			found++;

			bpf_map_delete_elem(map_fd, &addr);
		} else {
			missing++;
		}
	}

	if (missing)
		fprintf(stderr, "  warning: %d/%zu faults missing "
			"kernel timestamps\n", missing, num_pages);
}

/* ------------------------------------------------------------------ */
/*  Probe overhead calibration (unprobed run)                          */
/* ------------------------------------------------------------------ */

static int64_t run_calibration(size_t page_size, size_t warmup, int cpu,
			       int write_mode)
{
	size_t num_pages = CALIB_PAGES;
	size_t total = num_pages + warmup;
	size_t region_size = total * page_size;
	int64_t sum = 0;
	void *region;

	pin_to_cpu(cpu);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap calibration");
		return 0;
	}
	madvise(region, region_size, MADV_NOHUGEPAGE);

	for (size_t i = 0; i < total; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before, after;

		before = now_ns();
		if (write_mode)
			*p = 'B';
		else {
			char c = *p;
			(void)c;
		}
		after = now_ns();

		if (i >= warmup)
			sum += (int64_t)(after - before);
	}

	munmap(region, region_size);
	return sum / (int64_t)num_pages;
}

/* ------------------------------------------------------------------ */
/*  Baseline overhead breakdown benchmark                              */
/* ------------------------------------------------------------------ */

static void run_baseline_breakdown(size_t num_pages, size_t page_size,
				   size_t warmup, int cpu,
				   int use_kprobe, int csv,
				   int write_mode,
				   const char **phase_names,
				   const char **phase_csv_names,
				   int64_t timer_overhead_ns,
				   int64_t probe_overhead_ns)
{
	size_t total = num_pages + warmup;
	size_t region_size = total * page_size;
	struct fault_ts *ts;
	void *region;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;
	struct overhead_baseline_kprobe_bpf *skel = NULL;

	int64_t *phase_data = NULL;
	int64_t *phase_lat[NPHASES];
	int64_t *total_lat;

	pin_to_cpu(cpu);

	ts = calloc(total, sizeof(struct fault_ts));
	total_lat = calloc(num_pages, sizeof(int64_t));
	if (use_kprobe) {
		phase_data = calloc((size_t)NPHASES * num_pages,
				    sizeof(int64_t));
		for (int p = 0; p < NPHASES; p++)
			phase_lat[p] = &phase_data[(size_t)p * num_pages];
	}

	/* Set up the anonymous mmap region */
	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}
	madvise(region, region_size, MADV_NOHUGEPAGE);

	/* Set up and attach BPF probes */
	if (use_kprobe) {
		skel = bpf_setup(region, region_size);
		if (!skel) {
			fprintf(stderr, "  BPF setup failed, "
				"skipping phase breakdown\n");
			use_kprobe = 0;
		}
	}

	/* Fault phase */
	getrusage(RUSAGE_SELF, &ru_before);

	for (size_t i = 0; i < total; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		ts[i].t_fault_start = now_ns();
		if (write_mode)
			*p = 'B';
		else {
			char c = *p;
			(void)c;
		}
		ts[i].t_fault_done = now_ns();
	}

	getrusage(RUSAGE_SELF, &ru_after);

	/* Read BPF kernel timestamps */
	if (skel)
		bpf_read_timestamps(skel, ts, region, total, page_size);

	/* Compute per-fault latencies (skip warmup pages) */
	for (size_t i = warmup; i < total; i++) {
		size_t j = i - warmup;
		struct fault_ts *t = &ts[i];

		total_lat[j] = (int64_t)(t->t_fault_done - t->t_fault_start);

		if (!skel)
			continue;

		phase_lat[0][j] = phase_delta(t->t_hmf_entry, t->t_fault_start);
		phase_lat[1][j] = phase_delta(t->t_pte_missing, t->t_hmf_entry);
		phase_lat[2][j] = phase_delta(t->t_hmf_return, t->t_pte_missing);
		phase_lat[3][j] = phase_delta(t->t_fault_done, t->t_hmf_return);
	}

	/* Compute total average for percentage calculation */
	int64_t total_sum = 0;

	for (size_t i = 0; i < num_pages; i++)
		total_sum += total_lat[i];
	int64_t total_avg = total_sum / (int64_t)num_pages;

	/* Per-phase measurement overhead corrections */
	int64_t per_probe = 0;
	int64_t phase_corr[NPHASES];
	int64_t total_corr = 0;

	if (skel && probe_overhead_ns > 0 && total_avg > probe_overhead_ns)
		per_probe = (total_avg - probe_overhead_ns) / NUM_PROBE_HITS;

	for (int p = 0; p < NPHASES; p++) {
		int64_t sc = start_is_probe[p] ? per_probe
					       : timer_overhead_ns;
		int64_t ec = end_is_probe[p] ? per_probe
					     : timer_overhead_ns;
		phase_corr[p] = (sc + ec) / 2;
		total_corr += phase_corr[p];
	}

	/* CSV output mode */
	if (csv) {
		int64_t phase_sum[NPHASES] = {};

		if (skel)
			for (int p = 0; p < NPHASES; p++)
				for (size_t i = 0; i < num_pages; i++)
					phase_sum[p] += phase_lat[p][i];

		printf("%ld", (long)clamp_pos(total_avg - total_corr));
		if (skel)
			for (int p = 0; p < NPHASES; p++) {
				int64_t raw = phase_sum[p] /
					      (int64_t)num_pages;
				printf(",%ld",
				       (long)clamp_pos(raw - phase_corr[p]));
			}
		if (skel)
			printf(",%ld,%ld",
			       (long)timer_overhead_ns, (long)per_probe);
		printf("\n");
		goto out_stats_done;
	}

	/* Human-readable output */
	rd = rusage_diff(&ru_before, &ru_after);

	printf("  Baseline overhead breakdown (%zu pages, %zu warmup, "
	       "CPU %d, %s%s):\n\n",
	       num_pages, warmup, cpu,
	       write_mode ? "write faults" : "read faults",
	       skel ? ", BPF probes" : "");

	if (skel) {
		int64_t corr_total_avg = clamp_pos(total_avg - total_corr);

		printf("  %-40s %8s %8s %8s %8s %8s %7s %8s\n",
		       "Phase", "raw(ns)", "p50", "p99", "min", "max",
		       "%total", "corr");
		printf("  ─────────────────────────────────────"
		       "─── ──────── ──────── ──────── "
		       "──────── ──────── ─────── ────────\n");

		for (int p = 0; p < NPHASES; p++) {
			struct phase_stat s = compute_stat(phase_lat[p],
							   num_pages,
							   total_avg);
			int64_t corr = clamp_pos(s.avg - phase_corr[p]);

			printf("  %s. %-33s %8ld %8ld %8ld %8ld %8ld"
			       " %6.1f%% %7ld\n",
			       phase_prefix[p], phase_names[p],
			       (long)s.avg, (long)s.p50, (long)s.p99,
			       (long)s.min, (long)s.max, s.pct,
			       (long)corr);
		}

		printf("  ─────────────────────────────────────"
		       "─── ──────── ──────── ──────── "
		       "──────── ──────── ─────── ────────\n");

		{
			struct phase_stat s = compute_stat(total_lat,
							   num_pages,
							   total_avg);
			printf("  %-40s %8ld %8ld %8ld %8ld %8ld %6.1f%% %7ld\n",
			       "Total (end-to-end)",
			       (long)s.avg, (long)s.p50, (long)s.p99,
			       (long)s.min, (long)s.max, s.pct,
			       (long)corr_total_avg);
		}

		printf("\n  * corr = avg - measurement overhead "
		       "(timer: %ld ns, probe: %ld ns per hit)\n",
		       (long)timer_overhead_ns, (long)per_probe);
	}

	printf("\n");
	printf("  Context switches:  voluntary %ld  involuntary %ld\n",
	       rd.vol_csw, rd.invol_csw);
	printf("  Page faults:       minor %ld  major %ld\n",
	       rd.minflt, rd.majflt);
	printf("  Per-fault cost:    %ld ns/fault  (%.0f faults/sec)\n",
	       (long)total_avg,
	       num_pages / (total_sum / 1e9));

	if (skel) {
		printf("\n  What each sub-phase includes:\n");
		printf("     1.  Page fault exception -> "
		       "handle_mm_fault entry (arch dispatch)\n");
		printf("     2.  PGD/P4D/PUD/PMD page table walk, "
		       "PTE fault dispatch\n");
		if (write_mode)
			printf("     3.  vmf_anon_prepare, alloc_anon_folio, "
			       "rmap, LRU, set_ptes, unwind\n");
		else
			printf("     3.  pte_alloc, zero-page PFN, "
			       "set_ptes, unwind\n");
		printf("     4.  Architecture fault handler "
		       "returns to userspace\n");
	} else {
		printf("\n  Tip: use -k for 4-phase BPF-instrumented "
		       "breakdown\n");
	}

out_stats_done:
	munmap(region, region_size);
out:
	if (skel)
		overhead_baseline_kprobe_bpf__destroy(skel);
	free(phase_data);
	free(total_lat);
	free(ts);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-n pages] [-w warmup] [-r rounds] "
		"[-c cpu] [-k] [-W] [-C] [-o file]\n\n"
		"  -n  Pages to fault per round (default: 4096)\n"
		"  -w  Warmup pages to skip (default: 64)\n"
		"  -r  Rounds to run (default: 3)\n"
		"  -c  CPU to pin to (default: 0)\n"
		"  -k  Enable BPF instrumentation (4 sub-phases)\n"
		"  -W  Write faults (default: read faults / zero-page)\n"
		"  -C  CSV output (one row per round, averages)\n"
		"  -o  Write CSV output to file (default: stdout)\n",
		prog);
}

int main(int argc, char **argv)
{
	size_t num_pages = 4096;
	size_t warmup = 64;
	int rounds = 3;
	int cpu = 0;
	int csv = 0, use_kprobe = 0, write_mode = 0;
	const char *csv_path = NULL;
	long page_size = sysconf(_SC_PAGESIZE);
	int opt;

	while ((opt = getopt(argc, argv, "n:w:r:c:kWCo:h")) != -1) {
		switch (opt) {
		case 'n':
			num_pages = strtoul(optarg, NULL, 0);
			break;
		case 'w':
			warmup = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			rounds = atoi(optarg);
			break;
		case 'c':
			cpu = atoi(optarg);
			break;
		case 'k':
			use_kprobe = 1;
			break;
		case 'W':
			write_mode = 1;
			break;
		case 'C':
			csv = 1;
			break;
		case 'o':
			csv_path = optarg;
			csv = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	const char **pnames = write_mode ? phase_names_write
					 : phase_names_read;
	const char **pcsv = write_mode ? phase_csv_write
				       : phase_csv_read;
	const char *mode_str = write_mode
		? "write faults (page alloc)"
		: "read faults (zero-page)";

	if (!csv) {
		uint64_t timer_overhead = calibrate_timer();
		int64_t probe_overhead = 0;

		printf("Baseline fault overhead breakdown benchmark\n");
		printf("  Pages: %zu  Warmup: %zu  Rounds: %d  "
		       "Page size: %ld\n", num_pages, warmup, rounds,
		       page_size);
		printf("  CPU: %d\n", cpu);
		printf("  Fault mode: %s\n", mode_str);
		printf("  Mode: %s\n",
		       use_kprobe ? "BPF-instrumented (4 sub-phases)"
				  : "userspace timestamps only");
		printf("  Timer overhead: %lu ns/call\n",
		       (unsigned long)timer_overhead);

		if (use_kprobe) {
			printf("\n  Calibrating probe overhead "
			       "(%d pages, no BPF)...\n", CALIB_PAGES);
			probe_overhead = run_calibration(
				page_size, warmup, cpu, write_mode);
			printf("  Unprobed baseline latency: "
			       "%ld ns/fault\n", (long)probe_overhead);
		}
		printf("\n");

		for (int r = 0; r < rounds; r++) {
			printf("--- Round %d/%d ---\n\n", r + 1, rounds);
			run_baseline_breakdown(num_pages, page_size, warmup,
					       cpu, use_kprobe, 0,
					       write_mode, pnames, pcsv,
					       (int64_t)timer_overhead,
					       probe_overhead);
			printf("\n");
		}
	} else {
		uint64_t timer_overhead = calibrate_timer();
		int64_t unprobed_avg = 0;
		FILE *csv_fp = stdout;

		if (use_kprobe)
			unprobed_avg = run_calibration(
				page_size, warmup, cpu, write_mode);

		if (csv_path) {
			csv_fp = fopen(csv_path, "w");
			if (!csv_fp) {
				perror(csv_path);
				return 1;
			}
			if (dup2(fileno(csv_fp), STDOUT_FILENO) < 0) {
				perror("dup2");
				fclose(csv_fp);
				return 1;
			}
			fclose(csv_fp);
			fprintf(stderr, "Writing CSV to %s\n", csv_path);
		}

		/* Print CSV header */
		printf("fault_mode,total_avg_ns");
		if (use_kprobe)
			for (int p = 0; p < NPHASES; p++)
				printf(",%s_avg_ns", pcsv[p]);
		if (use_kprobe)
			printf(",timer_overhead_ns,probe_overhead_ns");
		printf("\n");

		for (int r = 0; r < rounds; r++) {
			printf("%s,", write_mode ? "write" : "read");
			run_baseline_breakdown(num_pages, page_size, warmup,
					       cpu, use_kprobe, 1,
					       write_mode, pnames, pcsv,
					       (int64_t)timer_overhead,
					       unprobed_avg);
		}
	}

	return 0;
}
