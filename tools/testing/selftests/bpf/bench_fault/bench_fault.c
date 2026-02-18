// SPDX-License-Identifier: GPL-2.0-only
/*
 * Benchmark: baseline vs userfaultfd vs bpf_fault page fault handling.
 *
 * Based on the userfaultfd(2) man page example.  The uffd and bpf paths
 * handle anonymous MISSING page faults by filling each page with 'A'.
 * The baseline measures the kernel's default anonymous page fault path.
 *
 * Metrics captured:
 *   - Total wall-clock time
 *   - Setup time (uffd/BPF registration)
 *   - Fault handling time (all pages touched)
 *   - Teardown time
 *   - Voluntary / involuntary context switches
 *   - Page faults (minor + major)
 *   - Per-fault latency (avg, min, max, p50, p99)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fault_ops.skel.h"

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

static struct rusage rusage_snap(void)
{
	struct rusage ru;
	getrusage(RUSAGE_SELF, &ru);
	return ru;
}

static struct rusage_delta rusage_diff(struct rusage *before,
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

static uint64_t *fault_latencies;  /* array[num_pages] */

static int cmp_u64(const void *a, const void *b)
{
	uint64_t va = *(const uint64_t *)a;
	uint64_t vb = *(const uint64_t *)b;
	return (va > vb) - (va < vb);
}

static void print_latency_stats(uint64_t *lat, size_t n)
{
	uint64_t sum = 0, min_v = UINT64_MAX, max_v = 0;

	if (!n) return;

	qsort(lat, n, sizeof(uint64_t), cmp_u64);

	for (size_t i = 0; i < n; i++) {
		sum += lat[i];
		if (lat[i] < min_v) min_v = lat[i];
		if (lat[i] > max_v) max_v = lat[i];
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
/*  baseline benchmark (anonymous faults, no uffd/bpf)           */
/* ------------------------------------------------------------------ */

static void bench_baseline(size_t num_pages, size_t page_size)
{
	size_t region_size = num_pages * page_size;
	void *region;
	uint64_t t_start, t_setup, t_faults, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== baseline benchmark (no uffd/bpf) ===\n");
	printf("  Pages: %zu  Page size: %zu  Region: %zu bytes\n",
	       num_pages, page_size, region_size);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	/* Setup phase: just mmap */
	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		free(fault_latencies);
		return;
	}

	t_setup = now_ns();

	/* Fault phase: touch each page sequentially */
	ru_before = rusage_snap();

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		char c = *p;  /* trigger the fault */
		uint64_t after = now_ns();
		fault_latencies[i] = after - before;
		(void)c;
	}

	ru_after = rusage_snap();
	t_faults = now_ns();

	t_end = t_faults;

	/* Verify: kernel zero-fills anonymous pages */
	int errors = 0;

	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;
		if (p[0] != 0) {
			errors++;
			if (errors <= 3)
				fprintf(stderr, "  page %zu: got 0x%02x expected 0x00\n",
					i, p[0]);
		}
	}
	if (errors)
		fprintf(stderr, "  VERIFICATION FAILED: %d pages wrong\n", errors);
	else
		printf("  Verification: OK\n");

	/* Results */
	rd = rusage_diff(&ru_before, &ru_after);
	printf("  Timings:\n");
	printf("    Setup:      %10.3f ms\n", (t_setup - t_start) / 1e6);
	printf("    Faults:     %10.3f ms\n", (t_faults - t_setup) / 1e6);
	printf("    Total:      %10.3f ms\n", (t_end - t_start) / 1e6);
	printf("    Throughput: %10.0f faults/sec\n",
	       num_pages / ((t_faults - t_setup) / 1e9));
	printf("  Context switches:\n");
	printf("    Voluntary:   %ld\n", rd.vol_csw);
	printf("    Involuntary: %ld\n", rd.invol_csw);
	printf("  Page faults:\n");
	printf("    Minor: %ld\n", rd.minflt);
	printf("    Major: %ld\n", rd.majflt);

	print_latency_stats(fault_latencies, num_pages);
	printf("\n");

	munmap(region, region_size);
	free(fault_latencies);
}

/* ------------------------------------------------------------------ */
/*  userfaultfd benchmark                                              */
/* ------------------------------------------------------------------ */

struct uffd_handler_args {
	int      uffd;
	size_t   page_size;
	size_t   num_pages;
	void    *region;
	volatile int done;
};

static void *uffd_handler_thread(void *arg)
{
	struct uffd_handler_args *ha = arg;
	struct uffdio_copy uc;
	char *src_page;
	ssize_t nread;

	src_page = mmap(NULL, ha->page_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (src_page == MAP_FAILED) {
		perror("mmap src_page");
		return NULL;
	}
	memset(src_page, FILL_BYTE, ha->page_size);

	for (;;) {
		struct uffd_msg msg;
		struct pollfd pfd = {
			.fd     = ha->uffd,
			.events = POLLIN,
		};

		if (poll(&pfd, 1, 100) <= 0) {
			if (ha->done)
				break;
			continue;
		}

		nread = read(ha->uffd, &msg, sizeof(msg));
		if (nread <= 0) {
			if (ha->done)
				break;
			if (nread < 0 && errno == EAGAIN)
				continue;
			break;
		}

		if (msg.event != UFFD_EVENT_PAGEFAULT)
			continue;

		uc.dst  = msg.arg.pagefault.address & ~(ha->page_size - 1);
		uc.src  = (unsigned long)src_page;
		uc.len  = ha->page_size;
		uc.mode = 0;
		uc.copy = 0;

		if (ioctl(ha->uffd, UFFDIO_COPY, &uc) < 0) {
			if (errno != EEXIST)
				perror("UFFDIO_COPY");
		}
	}

	munmap(src_page, ha->page_size);
	return NULL;
}

static void bench_userfaultfd(size_t num_pages, size_t page_size)
{
	size_t region_size = num_pages * page_size;
	void *region;
	int uffd;
	struct uffdio_api api;
	struct uffdio_register reg;
	pthread_t handler;
	struct uffd_handler_args ha;
	uint64_t t_start, t_setup, t_faults, t_teardown, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== userfaultfd benchmark ===\n");
	printf("  Pages: %zu  Page size: %zu  Region: %zu bytes\n",
	       num_pages, page_size, region_size);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	/* Setup phase */
	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return;
	}
	// madvise(region, region_size, MADV_NOHUGEPAGE);

	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0) {
		perror("userfaultfd");
		goto out_unmap;
	}

	api.api = UFFD_API;
	api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &api) < 0) {
		perror("UFFDIO_API");
		goto out_close;
	}

	reg.range.start = (unsigned long)region;
	reg.range.len   = region_size;
	reg.mode        = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) {
		perror("UFFDIO_REGISTER");
		goto out_close;
	}

	ha = (struct uffd_handler_args){
		.uffd      = uffd,
		.page_size = page_size,
		.num_pages = num_pages,
		.region    = region,
		.done      = 0,
	};
	pthread_create(&handler, NULL, uffd_handler_thread, &ha);

	t_setup = now_ns();

	/* Fault phase: touch each page sequentially */
	ru_before = rusage_snap();

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		char c = *p;  /* trigger the fault */
		uint64_t after = now_ns();
		fault_latencies[i] = after - before;
		(void)c;
	}

	ru_after = rusage_snap();
	t_faults = now_ns();

	/* Teardown */
	ha.done = 1;
	pthread_join(handler, NULL);
	close(uffd);

	t_teardown = now_ns();
	t_end = t_teardown;

	/* Verify */
	int errors = 0;
	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;
		if (p[0] != FILL_BYTE) {
			errors++;
			if (errors <= 3)
				fprintf(stderr, "  page %zu: got 0x%02x expected 0x%02x\n",
					i, p[0], FILL_BYTE);
		}
	}
	if (errors)
		fprintf(stderr, "  VERIFICATION FAILED: %d pages wrong\n", errors);
	else
		printf("  Verification: OK\n");

	/* Results */
	rd = rusage_diff(&ru_before, &ru_after);
	printf("  Timings:\n");
	printf("    Setup:      %10.3f ms\n", (t_setup - t_start) / 1e6);
	printf("    Faults:     %10.3f ms\n", (t_faults - t_setup) / 1e6);
	printf("    Teardown:   %10.3f ms\n", (t_teardown - t_faults) / 1e6);
	printf("    Total:      %10.3f ms\n", (t_end - t_start) / 1e6);
	printf("    Throughput: %10.0f faults/sec\n",
	       num_pages / ((t_faults - t_setup) / 1e9));
	printf("  Context switches:\n");
	printf("    Voluntary:   %ld\n", rd.vol_csw);
	printf("    Involuntary: %ld\n", rd.invol_csw);
	printf("  Page faults:\n");
	printf("    Minor: %ld\n", rd.minflt);
	printf("    Major: %ld\n", rd.majflt);

	print_latency_stats(fault_latencies, num_pages);
	printf("\n");

	munmap(region, region_size);
	free(fault_latencies);
	return;

out_close:
	close(uffd);
out_unmap:
	munmap(region, region_size);
	free(fault_latencies);
}

/* ------------------------------------------------------------------ */
/*  bpf_fault benchmark                                                */
/* ------------------------------------------------------------------ */

static void bench_bpf_fault(size_t num_pages, size_t page_size)
{
	size_t region_size = num_pages * page_size;
	void *region;
	struct fault_ops_bpf *skel;
	struct bpf_link *link;
	uint64_t t_start, t_setup, t_faults, t_teardown, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== bpf_fault benchmark ===\n");
	printf("  Pages: %zu  Page size: %zu  Region: %zu bytes\n",
	       num_pages, page_size, region_size);
	fflush(stdout);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	/* Setup phase */
	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return;
	}
	// madvise(region, region_size, MADV_NOHUGEPAGE);

	fprintf(stderr, "  [dbg] opening BPF skeleton...\n");
	fflush(stderr);
	skel = fault_ops_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		goto out_unmap;
	}
	fprintf(stderr, "  [dbg] open OK, loading...\n");

	if (fault_ops_bpf__load(skel)) {
		fprintf(stderr, "Failed to load BPF program: %s\n",
			strerror(errno));
		goto out_destroy;
	}
	fprintf(stderr, "  [dbg] load OK, attaching...\n");

	/*
	 * Attach the fault_ops struct_ops to our mmap'd region.
	 * This registers VM_BPF_FAULT on the VMA and creates the link.
	 */
	struct bpf_map *map = skel->maps.bench_fault_ops;

	link = bpf_map__attach_fault_ops(map, region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s (errno=%d)\n",
			strerror(errno), errno);
		goto out_destroy;
	}
	fprintf(stderr, "  [dbg] attach OK, faulting pages...\n");

	t_setup = now_ns();

	/* Fault phase: touch each page sequentially */
	ru_before = rusage_snap();

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		char c = *p;  /* trigger the fault */
		uint64_t after = now_ns();
		fault_latencies[i] = after - before;
		(void)c;
	}

	ru_after = rusage_snap();
	t_faults = now_ns();

	/* Teardown */
	bpf_link__destroy(link);
	fault_ops_bpf__destroy(skel);

	t_teardown = now_ns();
	t_end = t_teardown;

	/* Verify */
	int errors = 0;
	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;
		if (p[0] != FILL_BYTE) {
			errors++;
			if (errors <= 3)
				printf("  page %zu: got 0x%02x expected 0x%02x\n",
					i, p[0], FILL_BYTE);
		}
	}
	if (errors)
		printf("  VERIFICATION FAILED: %d pages wrong\n", errors);
	else
		printf("  Verification: OK\n");

	/* Results */
	rd = rusage_diff(&ru_before, &ru_after);
	printf("  Timings:\n");
	printf("    Setup:      %10.3f ms\n", (t_setup - t_start) / 1e6);
	printf("    Faults:     %10.3f ms\n", (t_faults - t_setup) / 1e6);
	printf("    Teardown:   %10.3f ms\n", (t_teardown - t_faults) / 1e6);
	printf("    Total:      %10.3f ms\n", (t_end - t_start) / 1e6);
	printf("    Throughput: %10.0f faults/sec\n",
	       num_pages / ((t_faults - t_setup) / 1e9));
	printf("  Context switches:\n");
	printf("    Voluntary:   %ld\n", rd.vol_csw);
	printf("    Involuntary: %ld\n", rd.invol_csw);
	printf("  Page faults:\n");
	printf("    Minor: %ld\n", rd.minflt);
	printf("    Major: %ld\n", rd.majflt);

	print_latency_stats(fault_latencies, num_pages);
	printf("\n");

	munmap(region, region_size);
	free(fault_latencies);
	return;

out_destroy:
	fault_ops_bpf__destroy(skel);
out_unmap:
	munmap(region, region_size);
	free(fault_latencies);
}

/* ------------------------------------------------------------------ */
/*  Main: run both benchmarks and compare                              */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr, "Usage: %s [-n num_pages] [-r rounds] [-b uffd|bpf|baseline|all]\n",
		prog);
	fprintf(stderr, "  -n  Number of pages to fault (default: 1024)\n");
	fprintf(stderr, "  -r  Number of rounds (default: 3)\n");
	fprintf(stderr, "  -b  Which benchmark: uffd, bpf, baseline, or all (default: all)\n");
}

int main(int argc, char **argv)
{
	size_t num_pages = 1024;
	int rounds = 3;
	int do_baseline = 1, do_uffd = 1, do_bpf = 1;
	long page_size = sysconf(_SC_PAGESIZE);
	int opt;

	while ((opt = getopt(argc, argv, "n:r:b:h")) != -1) {
		switch (opt) {
		case 'n':
			num_pages = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			rounds = atoi(optarg);
			break;
		case 'b':
			if (strcmp(optarg, "uffd") == 0) {
				do_baseline = 0;
				do_bpf = 0;
			} else if (strcmp(optarg, "bpf") == 0) {
				do_baseline = 0;
				do_uffd = 0;
			} else if (strcmp(optarg, "baseline") == 0) {
				do_uffd = 0;
				do_bpf = 0;
			} else if (strcmp(optarg, "all") != 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	printf("Page fault benchmark: %zu pages (%zu bytes), %d rounds\n\n",
	       num_pages, num_pages * page_size, rounds);

	for (int r = 0; r < rounds; r++) {
		printf("--- Round %d/%d ---\n\n", r + 1, rounds);

		if (do_baseline)
			bench_baseline(num_pages, page_size);
		if (do_uffd)
			bench_userfaultfd(num_pages, page_size);
		if (do_bpf)
			bench_bpf_fault(num_pages, page_size);
	}

	return 0;
}
