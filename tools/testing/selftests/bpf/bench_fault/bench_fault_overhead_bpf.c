// SPDX-License-Identifier: GPL-2.0-only
/*
 * bench_fault_overhead_bpf — bpf_fault fault-handling overhead breakdown.
 *
 * Dissects the per-fault latency of a bpf_fault MISSING fault into
 * 5 sub-phases using BPF kprobes and userspace timestamps.
 *
 * Unlike userfaultfd, bpf_fault runs entirely in the faulting thread's
 * context — no handler thread, no context switches, no IPC.
 *
 * Timeline for a single page fault (all timestamps marked):
 *
 *   Faulting thread (single CPU)
 *   ────────────────────────────
 *   t0: read page -> FAULT
 *       kernel: handle_mm_fault
 *         -> do_anonymous_page
 *   BF:   -> handle_bpf_fault          (BPF kprobe)
 *              release_fault_lock()
 *              folio_alloc()
 *              kmap_local_folio()
 *              [BPF struct_ops fills page]
 *              kunmap_local()
 *              flush_dcache_folio()
 *              __folio_mark_uptodate()
 *   LV:     bpf_fault_lock_vma()       (BPF kprobe)
 *              mem_cgroup_charge()
 *              bpf_fault_alloc_pmd()
 *   IP:     mfill_atomic_install_pte()  (BPF kprobe)
 *              bpf_fault_unlock_vma()
 *   BR:   handle_bpf_fault return       (BPF kretprobe)
 *   t5: back to userspace
 *
 * With -k (5 sub-phases):
 *    1  Fault dispatch       (t0->BF)   arch fault -> handle_bpf_fault
 *    2  Alloc + BPF program  (BF->LV)   release lock, alloc, BPF fill, flush
 *    3  VMA lock + pgtable   (LV->IP)   per-VMA lock, memcg, PMD walk
 *    4  PTE install          (IP->BR)   mfill_atomic_install_pte, unlock
 *    5  Kernel->user         (BR->t5)   fault return to userspace
 *
 * Also measures:
 *   - Baseline page fault cost (no bpf_fault, kernel zero-fill)
 *
 * Usage:
 *   ./bench_fault_overhead_bpf [-n pages] [-w warmup] [-r rounds]
 *                              [-c cpu] [-k] [-C] [-o file]
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

#include "fault_ops.skel.h"
#include "overhead_bpf_kprobe.skel.h"
#include "bench_fault_util.h"

#define NPHASES		5
#define NUM_PROBE_HITS	4	/* BPF probe firings per fault */
#define CALIB_PAGES	1024	/* pages for probe overhead calibration */

/* Matches struct bpf_overhead_ts in overhead_bpf_kprobe.bpf.c */
struct kernel_fault_ts {
	uint64_t t_bf_entry;
	uint64_t t_bf_return;
	uint64_t t_lock_vma;
	uint64_t t_install_pte;
};

struct fault_ts {
	uint64_t t_fault_start;		/* t0 */
	uint64_t t_fault_done;		/* t5 */
	uint64_t t_bf_entry;		/* BF */
	uint64_t t_bf_return;		/* BR */
	uint64_t t_lock_vma;		/* LV */
	uint64_t t_install_pte;		/* IP */
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
/*  Baseline benchmark (no bpf_fault — kernel zero-fill)               */
/* ------------------------------------------------------------------ */

static int64_t run_baseline(size_t num_pages, size_t page_size,
			    size_t warmup, int cpu)
{
	size_t total = num_pages + warmup;
	size_t region_size = total * page_size;
	int64_t *lat;
	int64_t sum = 0;
	void *region;

	pin_to_cpu(cpu);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap baseline");
		return 0;
	}
	madvise(region, region_size, MADV_NOHUGEPAGE);

	lat = calloc(num_pages, sizeof(int64_t));

	for (size_t i = 0; i < total; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		char c = *p;
		uint64_t after = now_ns();

		(void)c;
		if (i >= warmup)
			lat[i - warmup] = (int64_t)(after - before);
	}

	qsort(lat, num_pages, sizeof(int64_t), cmp_i64);
	for (size_t i = 0; i < num_pages; i++)
		sum += lat[i];

	int64_t avg = sum / (int64_t)num_pages;

	printf("  Baseline (kernel zero-fill):  avg %ld ns   p50 %ld ns   "
	       "p99 %ld ns   min %ld ns   max %ld ns\n",
	       (long)avg, (long)lat[num_pages / 2],
	       (long)lat[(size_t)(num_pages * 0.99)],
	       (long)lat[0], (long)lat[num_pages - 1]);

	munmap(region, region_size);
	free(lat);
	return avg;
}

/* ------------------------------------------------------------------ */
/*  Phase definitions                                                  */
/* ------------------------------------------------------------------ */

static const char *phase_names[NPHASES] = {
	"Fault dispatch       (t0->BF)",
	"Alloc + BPF program  (BF->LV)",
	"VMA lock + pgtable   (LV->IP)",
	"PTE install          (IP->BR)",
	"Kernel->user         (BR->t5)",
};

static const char *phase_csv[NPHASES] = {
	"fault_dispatch", "alloc_bpf_prog",
	"vma_lock_pgtable", "pte_install",
	"kernel_to_user",
};

static const char *phase_prefix[NPHASES] = {
	"  1", "  2", "  3", "  4", "  5",
};

/*
 * Probe boundary types for measurement overhead correction.
 *
 * Phase  Start     End
 *  0     t0(tmr)   BF(kp)       0    1
 *  1     BF(kp)    LV(kp)       1    1
 *  2     LV(kp)    IP(kp)       1    1
 *  3     IP(kp)    BR(krp)      1    1
 *  4     BR(krp)   t5(tmr)      1    0
 */
static const int start_is_probe[NPHASES] = {
	0, 1, 1, 1, 1
};
static const int end_is_probe[NPHASES] = {
	1, 1, 1, 1, 0
};

/* ------------------------------------------------------------------ */
/*  bpf_fault setup helpers                                            */
/* ------------------------------------------------------------------ */

struct bpf_fault_setup {
	struct fault_ops_bpf *skel;
	struct bpf_link *link;
};

static int setup_bpf_fault(struct bpf_fault_setup *setup,
			   void *region, size_t region_size)
{
	struct bpf_map *map;

	setup->skel = fault_ops_bpf__open();
	if (!setup->skel) {
		fprintf(stderr, "  error: failed to open fault_ops skeleton\n");
		return -1;
	}

	if (fault_ops_bpf__load(setup->skel)) {
		fprintf(stderr, "  error: fault_ops load failed: %s\n",
			strerror(errno));
		goto err_destroy;
	}

	map = setup->skel->maps.bench_fault_ops;
	setup->link = bpf_map__attach_fault_ops(map, region, region_size, 0);
	if (!setup->link) {
		fprintf(stderr, "  error: fault_ops attach failed: %s\n",
			strerror(errno));
		goto err_destroy;
	}

	return 0;

err_destroy:
	fault_ops_bpf__destroy(setup->skel);
	setup->skel = NULL;
	return -1;
}

static void teardown_bpf_fault(struct bpf_fault_setup *setup)
{
	if (setup->link)
		bpf_link__destroy(setup->link);
	if (setup->skel)
		fault_ops_bpf__destroy(setup->skel);
}

/* ------------------------------------------------------------------ */
/*  BPF kprobe setup / readback                                        */
/* ------------------------------------------------------------------ */

static struct overhead_bpf_kprobe_bpf *kprobe_setup(void)
{
	struct overhead_bpf_kprobe_bpf *skel;

	skel = overhead_bpf_kprobe_bpf__open();
	if (!skel) {
		fprintf(stderr, "  error: failed to open kprobe skeleton\n");
		return NULL;
	}

	skel->rodata->target_tgid = getpid();

	if (overhead_bpf_kprobe_bpf__load(skel)) {
		fprintf(stderr, "  error: kprobe BPF load failed: %s\n",
			strerror(errno));
		overhead_bpf_kprobe_bpf__destroy(skel);
		return NULL;
	}

	if (overhead_bpf_kprobe_bpf__attach(skel)) {
		fprintf(stderr, "  error: kprobe BPF attach failed: %s\n"
			"  (bpf_fault_lock_vma may need "
			"CONFIG_KALLSYMS_ALL=y)\n", strerror(errno));
		overhead_bpf_kprobe_bpf__destroy(skel);
		return NULL;
	}

	return skel;
}

static void kprobe_read_timestamps(struct overhead_bpf_kprobe_bpf *skel,
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
			ts[i].t_bf_entry    = kts.t_bf_entry;
			ts[i].t_bf_return   = kts.t_bf_return;
			ts[i].t_lock_vma    = kts.t_lock_vma;
			ts[i].t_install_pte = kts.t_install_pte;
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
/*  Probe overhead calibration (unprobed bpf_fault run)                */
/* ------------------------------------------------------------------ */

static int64_t run_bpf_calibration(size_t page_size, size_t warmup, int cpu)
{
	size_t num_pages = CALIB_PAGES;
	size_t total = num_pages + warmup;
	size_t region_size = total * page_size;
	struct bpf_fault_setup bf = {};
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

	if (setup_bpf_fault(&bf, region, region_size)) {
		munmap(region, region_size);
		return 0;
	}

	for (size_t i = 0; i < total; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		char c = *p;
		uint64_t after = now_ns();

		(void)c;
		if (i >= warmup)
			sum += (int64_t)(after - before);
	}

	teardown_bpf_fault(&bf);
	munmap(region, region_size);
	return sum / (int64_t)num_pages;
}

/* ------------------------------------------------------------------ */
/*  bpf_fault overhead breakdown benchmark                             */
/* ------------------------------------------------------------------ */

static void run_bpf_breakdown(size_t num_pages, size_t page_size,
			      size_t warmup, int cpu,
			      int use_kprobe, int csv,
			      int64_t baseline_avg,
			      int64_t timer_overhead_ns,
			      int64_t probe_overhead_ns)
{
	size_t total = num_pages + warmup;
	size_t region_size = total * page_size;
	struct fault_ts *ts;
	void *region;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;
	struct bpf_fault_setup bf = {};
	struct overhead_bpf_kprobe_bpf *skel = NULL;

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

	/* Set up bpf_fault link on the region */
	if (setup_bpf_fault(&bf, region, region_size)) {
		fprintf(stderr, "  bpf_fault setup failed\n");
		goto out_unmap;
	}

	/* Set up BPF kprobes for instrumentation */
	if (use_kprobe) {
		skel = kprobe_setup();
		if (!skel) {
			fprintf(stderr, "  kprobe setup failed, "
				"skipping phase breakdown\n");
			use_kprobe = 0;
		}
	}

	/* Fault phase: read each page sequentially */
	getrusage(RUSAGE_SELF, &ru_before);

	for (size_t i = 0; i < total; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		ts[i].t_fault_start = now_ns();
		char c = *p;
		ts[i].t_fault_done = now_ns();
		(void)c;
	}

	getrusage(RUSAGE_SELF, &ru_after);

	/* Detach kprobes before teardown */
	if (skel) {
		kprobe_read_timestamps(skel, ts, region, total, page_size);
		overhead_bpf_kprobe_bpf__destroy(skel);
		skel = NULL;
	}

	/* Verify page contents */
	int errors = 0;

	for (size_t i = 0; i < total; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;

		if (p[0] != FILL_BYTE) {
			errors++;
			if (errors <= 3)
				fprintf(stderr, "  page %zu: got 0x%02x "
					"expected 0x%02x\n",
					i, p[0], FILL_BYTE);
		}
	}
	if (errors)
		fprintf(stderr, "  VERIFICATION FAILED: %d pages\n", errors);

	/* Teardown bpf_fault */
	teardown_bpf_fault(&bf);

	/* Compute per-fault latencies (skip warmup pages) */
	for (size_t i = warmup; i < total; i++) {
		size_t j = i - warmup;
		struct fault_ts *t = &ts[i];

		total_lat[j] = (int64_t)(t->t_fault_done - t->t_fault_start);

		if (!use_kprobe)
			continue;

		phase_lat[0][j] = phase_delta(t->t_bf_entry, t->t_fault_start);
		phase_lat[1][j] = phase_delta(t->t_lock_vma, t->t_bf_entry);
		phase_lat[2][j] = phase_delta(t->t_install_pte, t->t_lock_vma);
		phase_lat[3][j] = phase_delta(t->t_bf_return, t->t_install_pte);
		phase_lat[4][j] = phase_delta(t->t_fault_done, t->t_bf_return);
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

	if (use_kprobe && probe_overhead_ns > 0 &&
	    total_avg > probe_overhead_ns)
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

		if (use_kprobe)
			for (int p = 0; p < NPHASES; p++)
				for (size_t i = 0; i < num_pages; i++)
					phase_sum[p] += phase_lat[p][i];

		printf("%ld", (long)clamp_pos(total_avg - total_corr));
		if (use_kprobe)
			for (int p = 0; p < NPHASES; p++) {
				int64_t raw = phase_sum[p] /
					      (int64_t)num_pages;
				printf(",%ld",
				       (long)clamp_pos(raw - phase_corr[p]));
			}
		if (use_kprobe)
			printf(",%ld,%ld",
			       (long)timer_overhead_ns, (long)per_probe);
		printf("\n");
		goto out_stats_done;
	}

	/* Human-readable output */
	rd = rusage_diff(&ru_before, &ru_after);

	printf("  bpf_fault overhead breakdown (%zu pages, %zu warmup, "
	       "CPU %d%s):\n\n",
	       num_pages, warmup, cpu,
	       use_kprobe ? ", BPF probes" : "");

	if (use_kprobe) {
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

	if (baseline_avg > 0)
		printf("  vs baseline:       %.1fx overhead  "
		       "(baseline: %ld ns/fault)\n",
		       (double)total_avg / baseline_avg,
		       (long)baseline_avg);

	if (use_kprobe) {
		printf("\n  What each sub-phase includes:\n");
		printf("     1.  Page fault exception -> "
		       "do_anonymous_page -> handle_bpf_fault entry\n");
		printf("     2.  release_fault_lock, folio_alloc, "
		       "kmap, BPF program fills page, kunmap, flush\n");
		printf("     3.  bpf_fault_lock_vma (per-VMA lock), "
		       "mem_cgroup_charge, PMD walk\n");
		printf("     4.  mfill_atomic_install_pte: PTE lock, "
		       "set_pte_at, rmap, LRU, unlock\n");
		printf("     5.  handle_bpf_fault return, fault "
		       "unwinds to userspace\n");
	} else {
		printf("\n  Tip: use -k for 5-phase BPF-instrumented "
		       "breakdown\n");
	}

out_stats_done:
	munmap(region, region_size);
out_unmap:
out:
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
		"[-c cpu] [-k] [-C] [-o file]\n\n"
		"  -n  Pages to fault per round (default: 4096)\n"
		"  -w  Warmup pages to skip (default: 64)\n"
		"  -r  Rounds to run (default: 3)\n"
		"  -c  CPU to pin to (default: 0)\n"
		"  -k  Enable BPF instrumentation (5 sub-phases)\n"
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
	int csv = 0, use_kprobe = 0;
	const char *csv_path = NULL;
	long page_size = sysconf(_SC_PAGESIZE);
	int opt;

	while ((opt = getopt(argc, argv, "n:w:r:c:kCo:h")) != -1) {
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

	if (!csv) {
		uint64_t timer_overhead = calibrate_timer();
		int64_t probe_overhead = 0;

		printf("bpf_fault overhead breakdown benchmark\n");
		printf("  Pages: %zu  Warmup: %zu  Rounds: %d  "
		       "Page size: %ld\n", num_pages, warmup, rounds,
		       page_size);
		printf("  CPU: %d\n", cpu);
		printf("  Mode: %s\n",
		       use_kprobe ? "BPF-instrumented (5 sub-phases)"
				  : "userspace timestamps only");
		printf("  Timer overhead: %lu ns/call\n",
		       (unsigned long)timer_overhead);

		if (use_kprobe) {
			printf("\n  Calibrating probe overhead "
			       "(%d pages, no kprobes)...\n", CALIB_PAGES);
			probe_overhead = run_bpf_calibration(
				page_size, warmup, cpu);
			printf("  Unprobed bpf_fault latency: "
			       "%ld ns/fault\n", (long)probe_overhead);
		}
		printf("\n");

		for (int r = 0; r < rounds; r++) {
			printf("--- Round %d/%d ---\n\n", r + 1, rounds);

			int64_t baseline_avg = run_baseline(num_pages,
							    page_size,
							    warmup, cpu);
			printf("\n");

			run_bpf_breakdown(num_pages, page_size, warmup,
					  cpu, use_kprobe, 0,
					  baseline_avg,
					  (int64_t)timer_overhead,
					  probe_overhead);
			printf("\n");
		}
	} else {
		uint64_t timer_overhead = calibrate_timer();
		int64_t unprobed_avg = 0;
		FILE *csv_fp = stdout;

		if (use_kprobe)
			unprobed_avg = run_bpf_calibration(
				page_size, warmup, cpu);

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
		printf("total_avg_ns");
		if (use_kprobe)
			for (int p = 0; p < NPHASES; p++)
				printf(",%s_avg_ns", phase_csv[p]);
		if (use_kprobe)
			printf(",timer_overhead_ns,probe_overhead_ns");
		printf("\n");

		for (int r = 0; r < rounds; r++)
			run_bpf_breakdown(num_pages, page_size, warmup,
					  cpu, use_kprobe, 1,
					  0,
					  (int64_t)timer_overhead,
					  unprobed_avg);
	}

	return 0;
}
