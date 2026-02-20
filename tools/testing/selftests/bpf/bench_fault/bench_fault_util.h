/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared utilities for bench_fault benchmarks.
 *
 * Provides timing helpers, rusage tracking, per-fault latency statistics,
 * result printing, and tmpfs discovery.  All functions are static to avoid
 * linker conflicts when included from multiple single-file programs.
 */
#ifndef BENCH_FAULT_UTIL_H
#define BENCH_FAULT_UTIL_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>

#define FILL_BYTE 'A'

/* ------------------------------------------------------------------ */
/*  Timing helpers                                                     */
/* ------------------------------------------------------------------ */

static inline uint64_t now_ns(void)
{
	struct timespec ts;

	clock_gettime(CLOCK_MONOTONIC, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

struct rusage_delta {
	long vol_csw;
	long invol_csw;
	long minflt;
	long majflt;
};

static inline struct rusage rusage_snap(void)
{
	struct rusage ru;

	getrusage(RUSAGE_SELF, &ru);
	return ru;
}

static inline struct rusage_delta rusage_diff(struct rusage *before,
		struct rusage *after)
{
	return (struct rusage_delta){
		.vol_csw   = after->ru_nvcsw   - before->ru_nvcsw,
		.invol_csw = after->ru_nivcsw  - before->ru_nivcsw,
		.minflt    = after->ru_minflt  - before->ru_minflt,
		.majflt    = after->ru_majflt  - before->ru_majflt,
	};
}

/* ------------------------------------------------------------------ */
/*  Per-fault latency tracking                                         */
/* ------------------------------------------------------------------ */

static inline int cmp_u64(const void *a, const void *b)
{
	uint64_t va = *(const uint64_t *)a;
	uint64_t vb = *(const uint64_t *)b;

	return (va > vb) - (va < vb);
}

static inline void print_latency_stats(uint64_t *lat, size_t n)
{
	uint64_t sum = 0, min_v = UINT64_MAX, max_v = 0;

	if (!n)
		return;

	qsort(lat, n, sizeof(uint64_t), cmp_u64);

	for (size_t i = 0; i < n; i++) {
		sum += lat[i];
		if (lat[i] < min_v)
			min_v = lat[i];
		if (lat[i] > max_v)
			max_v = lat[i];
	}

	printf("    Per-fault latency (ns):\n");
	printf("      avg:  %lu\n", sum / n);
	printf("      min:  %lu\n", min_v);
	printf("      max:  %lu\n", max_v);
	printf("      p50:  %lu\n", lat[n / 2]);
	printf("      p99:  %lu\n", lat[(size_t)(n * 0.99)]);
	printf("      p999: %lu\n", lat[(size_t)(n * 0.999)]);
}

/* ------------------------------------------------------------------ */
/*  Result printing                                                    */
/* ------------------------------------------------------------------ */

static inline void print_results(const char *label, size_t num_pages,
			   uint64_t t_start, uint64_t t_setup,
			   uint64_t t_faults, uint64_t t_teardown,
			   struct rusage_delta *rd, uint64_t *lat,
			   size_t n_lat, size_t sig_faults)
{
	printf("  Timings:\n");
	printf("    Setup:      %10.3f ms\n", (t_setup - t_start) / 1e6);
	printf("    Faults:     %10.3f ms\n", (t_faults - t_setup) / 1e6);
	if (t_teardown > t_faults)
		printf("    Teardown:   %10.3f ms\n",
		       (t_teardown - t_faults) / 1e6);
	printf("    Total:      %10.3f ms\n", (t_teardown - t_start) / 1e6);
	printf("    Throughput: %10.0f faults/sec\n",
	       num_pages / ((t_faults - t_setup) / 1e9));
	printf("  Context switches:\n");
	printf("    Voluntary:   %ld\n", rd->vol_csw);
	printf("    Involuntary: %ld\n", rd->invol_csw);
	printf("  Page faults:\n");
	printf("    Minor: %ld\n", rd->minflt);
	printf("    Major: %ld\n", rd->majflt);
	if (sig_faults)
		printf("    SIGSEGV: %zu\n", sig_faults);

	print_latency_stats(lat, n_lat);
	printf("\n");
}

/* ------------------------------------------------------------------ */
/*  tmpfs helpers                                                      */
/* ------------------------------------------------------------------ */

static inline const char *find_tmpfs(void)
{
	struct stat st;

	if (stat("/dev/shm", &st) == 0)
		return "/dev/shm";
	return "/tmp";
}

#endif /* BENCH_FAULT_UTIL_H */
