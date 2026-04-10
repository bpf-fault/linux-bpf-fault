// SPDX-License-Identifier: GPL-2.0-only
/*
 * Benchmark: write-protect fault handling.
 *
 * Compares three mechanisms for intercepting writes to pre-populated pages:
 *
 *   1. bpf_fault WP    — BPF handle_wp_fault callback, handled in-kernel
 *   2. userfaultfd WP  — uffd WP registration, handler thread resolves
 *   3. SIGSEGV+mprotect — mprotect(PROT_READ), SIGSEGV handler re-enables
 *
 * All three follow the same pattern:
 *   - mmap + populate pages (normal zero-fill)
 *   - write-protect the region
 *   - sequentially write to each page, measuring per-fault latency
 *
 * Metrics: wall-clock time, throughput, per-fault latency (avg/min/max/p50/p99).
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

#include "wp_fault_ops.skel.h"
#include "bench_fault_util.h"
#include "wp_util.h"

static uint64_t *fault_latencies;

static long page_size;

/*
 * Populate pages by reading each one (forces zero-page COW allocation
 * for anonymous mappings, or populates shared pages for non-anon).
 * Write to make sure each page has a private copy (not zero page).
 */
static void populate_pages(void *region, size_t num_pages)
{
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		*p = 'P';
	}
}

/* ------------------------------------------------------------------ */
/*  Benchmark: bpf_fault WP                                            */
/* ------------------------------------------------------------------ */

static void bench_bpf_wp(size_t num_pages)
{
	size_t region_size = num_pages * page_size;
	struct wp_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = NULL;
	uint64_t t_start, t_setup, t_faults, t_teardown;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== bpf_fault WP benchmark ===\n");
	printf("  Pages: %zu  Page size: %ld  Region: %zu bytes\n",
	       num_pages, page_size, region_size);
	fflush(stdout);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	region = alloc_anon_region(region_size);
	if (!region)
		goto out;

	skel = wp_fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.wp_fault_ops,
					 region, region_size,
					 BPF_FAULT_FLAG_WP);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	populate_pages(region, num_pages);

	/* Write-protect all pages */
	if (bpf_link_writeprotect(bpf_link__fd(link), (unsigned long)region,
				  region_size, BPF_FAULT_WP_ENABLE) < 0) {
		fprintf(stderr, "BPF_LINK_WRITEPROTECT enable failed: %s\n",
			strerror(errno));
		goto out;
	}

	t_setup = now_ns();

	/* Fault phase: write to each page — triggers BPF WP fault */
	ru_before = rusage_snap();

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		*p = 'W';
		uint64_t after = now_ns();

		fault_latencies[i] = after - before;
	}

	ru_after = rusage_snap();
	t_faults = now_ns();

	/* Teardown */
	bpf_link__destroy(link);
	link = NULL;
	wp_fault_ops_bpf__destroy(skel);
	skel = NULL;

	t_teardown = now_ns();

	rd = rusage_diff(&ru_before, &ru_after);
	print_results("bpf_wp", num_pages, t_start, t_setup,
		      t_faults, t_teardown, &rd, fault_latencies, num_pages, 0);

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		wp_fault_ops_bpf__destroy(skel);
	if (region)
		munmap(region, region_size);
	free(fault_latencies);
	fault_latencies = NULL;
}

/* ------------------------------------------------------------------ */
/*  Benchmark: userfaultfd WP                                          */
/* ------------------------------------------------------------------ */

struct uffd_wp_handler_args {
	int		uffd;
	volatile int	done;
};

static void *uffd_wp_handler_thread(void *arg)
{
	struct uffd_wp_handler_args *ha = arg;

	for (;;) {
		struct uffd_msg msg;
		struct pollfd pfd = {
			.fd	= ha->uffd,
			.events	= POLLIN,
		};
		ssize_t nread;

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

		/*
		 * Resolve the WP fault: remove write protection on
		 * the faulting page so the write can proceed.
		 */
		struct uffdio_writeprotect wp;
		unsigned long fault_addr;

		fault_addr = msg.arg.pagefault.address &
			     ~((unsigned long)sysconf(_SC_PAGESIZE) - 1);

		wp.range.start = fault_addr;
		wp.range.len = sysconf(_SC_PAGESIZE);
		wp.mode = 0; /* remove WP */

		if (ioctl(ha->uffd, UFFDIO_WRITEPROTECT, &wp) < 0) {
			if (errno != ENOENT)
				perror("UFFDIO_WRITEPROTECT resolve");
		}
	}

	return NULL;
}

static void bench_uffd_wp(size_t num_pages)
{
	size_t region_size = num_pages * page_size;
	void *region = NULL;
	int uffd = -1;
	struct uffdio_api api;
	struct uffdio_register reg;
	struct uffdio_writeprotect wp;
	pthread_t handler;
	struct uffd_wp_handler_args ha;
	int handler_started = 0;
	uint64_t t_start, t_setup, t_faults, t_teardown;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== userfaultfd WP benchmark ===\n");
	printf("  Pages: %zu  Page size: %ld  Region: %zu bytes\n",
	       num_pages, page_size, region_size);
	fflush(stdout);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	region = alloc_anon_region(region_size);
	if (!region)
		goto out;

	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0) {
		perror("userfaultfd");
		goto out;
	}

	api.api = UFFD_API;
	api.features = UFFD_FEATURE_PAGEFAULT_FLAG_WP;
	if (ioctl(uffd, UFFDIO_API, &api) < 0) {
		perror("UFFDIO_API");
		goto out;
	}

	/* Populate pages before registration */
	populate_pages(region, num_pages);

	/* Register for WP only (not MISSING) */
	reg.range.start = (unsigned long)region;
	reg.range.len = region_size;
	reg.mode = UFFDIO_REGISTER_MODE_WP;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) {
		perror("UFFDIO_REGISTER (WP)");
		goto out;
	}

	/* Write-protect the region */
	wp.range.start = (unsigned long)region;
	wp.range.len = region_size;
	wp.mode = UFFDIO_WRITEPROTECT_MODE_WP;
	if (ioctl(uffd, UFFDIO_WRITEPROTECT, &wp) < 0) {
		perror("UFFDIO_WRITEPROTECT enable");
		goto out;
	}

	/* Start handler thread */
	ha = (struct uffd_wp_handler_args){
		.uffd = uffd,
		.done = 0,
	};
	pthread_create(&handler, NULL, uffd_wp_handler_thread, &ha);
	handler_started = 1;

	t_setup = now_ns();

	/* Fault phase: write to each page — triggers uffd WP fault */
	ru_before = rusage_snap();

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		*p = 'W';
		uint64_t after = now_ns();

		fault_latencies[i] = after - before;
	}

	ru_after = rusage_snap();
	t_faults = now_ns();

	/* Teardown */
	ha.done = 1;
	pthread_join(handler, NULL);
	close(uffd);
	uffd = -1;

	t_teardown = now_ns();

	rd = rusage_diff(&ru_before, &ru_after);
	print_results("uffd_wp", num_pages, t_start, t_setup,
		      t_faults, t_teardown, &rd, fault_latencies, num_pages, 0);

out:
	if (handler_started) {
		ha.done = 1;
		pthread_join(handler, NULL);
	}
	if (uffd >= 0)
		close(uffd);
	if (region)
		munmap(region, region_size);
	free(fault_latencies);
	fault_latencies = NULL;
}

/* ------------------------------------------------------------------ */
/*  Benchmark: SIGSEGV + mprotect                                      */
/* ------------------------------------------------------------------ */

/*
 * Per-thread state for the signal handler.  Since SIGSEGV is delivered
 * to the faulting thread, we use a single global (single-threaded bench).
 */
static void *sig_region;
static size_t sig_region_size;
static volatile size_t sig_fault_count;

static void sigsegv_handler(int sig, siginfo_t *si, void *ctx)
{
	unsigned long addr = (unsigned long)si->si_addr;
	unsigned long page_addr = addr & ~(page_size - 1);

	/*
	 * Re-enable write on the faulting page.  This is the equivalent
	 * of the uffd handler resolving the WP fault.
	 */
	mprotect((void *)page_addr, page_size, PROT_READ | PROT_WRITE);
	sig_fault_count++;
}

static void bench_sigsegv_wp(size_t num_pages)
{
	size_t region_size = num_pages * page_size;
	void *region = NULL;
	struct sigaction sa, old_sa;
	uint64_t t_start, t_setup, t_faults, t_teardown;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== SIGSEGV+mprotect WP benchmark ===\n");
	printf("  Pages: %zu  Page size: %ld  Region: %zu bytes\n",
	       num_pages, page_size, region_size);
	fflush(stdout);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	region = alloc_anon_region(region_size);
	if (!region)
		goto out;

	populate_pages(region, num_pages);

	/* Install SIGSEGV handler */
	sig_region = region;
	sig_region_size = region_size;
	sig_fault_count = 0;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigsegv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSEGV, &sa, &old_sa) < 0) {
		perror("sigaction");
		goto out;
	}

	/* Write-protect via mprotect */
	if (mprotect(region, region_size, PROT_READ) < 0) {
		perror("mprotect(PROT_READ)");
		sigaction(SIGSEGV, &old_sa, NULL);
		goto out;
	}

	t_setup = now_ns();

	/* Fault phase: write to each page — triggers SIGSEGV */
	ru_before = rusage_snap();

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		*p = 'W';
		uint64_t after = now_ns();

		fault_latencies[i] = after - before;
	}

	ru_after = rusage_snap();
	t_faults = now_ns();

	/* Teardown — restore default handler */
	sigaction(SIGSEGV, &old_sa, NULL);

	t_teardown = now_ns();

	rd = rusage_diff(&ru_before, &ru_after);
	print_results("sigsegv_wp", num_pages, t_start, t_setup,
		      t_faults, t_teardown, &rd, fault_latencies, num_pages, sig_fault_count);

out:
	if (region)
		munmap(region, region_size);
	free(fault_latencies);
	fault_latencies = NULL;
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-n num_pages] [-r rounds] [-b bpf|uffd|sigsegv|all]\n",
		prog);
	fprintf(stderr, "  -n  Number of pages to fault (default: 1024)\n");
	fprintf(stderr, "  -r  Number of rounds (default: 3)\n");
	fprintf(stderr, "  -b  Which benchmark: bpf, uffd, sigsegv, or all (default: all)\n");
}

int main(int argc, char **argv)
{
	size_t num_pages = 1024;
	int rounds = 3;
	int do_bpf = 1, do_uffd = 1, do_sigsegv = 1;
	int opt;

	page_size = sysconf(_SC_PAGESIZE);

	while ((opt = getopt(argc, argv, "n:r:b:h")) != -1) {
		switch (opt) {
		case 'n':
			num_pages = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			rounds = atoi(optarg);
			break;
		case 'b':
			if (strcmp(optarg, "bpf") == 0) {
				do_uffd = 0;
				do_sigsegv = 0;
			} else if (strcmp(optarg, "uffd") == 0) {
				do_bpf = 0;
				do_sigsegv = 0;
			} else if (strcmp(optarg, "sigsegv") == 0) {
				do_bpf = 0;
				do_uffd = 0;
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

	printf("WP fault benchmark: %zu pages (%zu bytes), %d rounds\n\n",
	       num_pages, num_pages * page_size, rounds);

	for (int r = 0; r < rounds; r++) {
		printf("--- Round %d/%d ---\n\n", r + 1, rounds);

		if (do_bpf)
			bench_bpf_wp(num_pages);
		if (do_uffd)
			bench_uffd_wp(num_pages);
		if (do_sigsegv)
			bench_sigsegv_wp(num_pages);
	}

	return 0;
}
