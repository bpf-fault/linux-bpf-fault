// SPDX-License-Identifier: GPL-2.0-only
/*
 * Benchmark: baseline vs userfaultfd vs bpf_fault page fault handling.
 *
 * Based on the userfaultfd(2) man page example.  The uffd and bpf paths
 * handle anonymous MISSING page faults by filling each page with 'A'.
 * The baseline measures the kernel's default anonymous page fault path.
 *
 * Two fault modes:
 *   Read  (default): read triggers fault; handlers resolve with zeros.
 *     - baseline:  kernel zero-page map
 *     - uffd:      UFFDIO_ZEROPAGE
 *     - sigsegv:   mprotect only (zero page on retry)
 *     - bpf_fault: BPF returns without filling (page stays zeroed)
 *
 *   Write (-W): read triggers fault; handlers resolve with data copy.
 *     - baseline:  kernel page allocation (write fault)
 *     - uffd:      UFFDIO_COPY (copies 'A'-filled page)
 *     - sigsegv:   mprotect + memset (fills page with 'A')
 *     - bpf_fault: BPF fills page with 'A'
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
#include "bench_fault_util.h"

static uint64_t *fault_latencies;

/* ------------------------------------------------------------------ */
/*  Fault trigger helper                                               */
/* ------------------------------------------------------------------ */

static inline void trigger_fault(volatile char *p, int write_mode,
				size_t page_size)
{
	if (write_mode)
		memset((void *)p, FILL_BYTE, page_size);
	else {
		char c = *p;
		(void)c;
	}
}

/* ------------------------------------------------------------------ */
/*  baseline benchmark (anonymous faults, no uffd/bpf)                 */
/* ------------------------------------------------------------------ */

static void bench_baseline(size_t num_pages, size_t page_size, int write_mode)
{
	size_t region_size = num_pages * page_size;
	void *region;
	uint64_t t_start, t_setup, t_faults, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== baseline benchmark (%s faults) ===\n",
	       write_mode ? "write" : "read");
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

		trigger_fault(p, write_mode, page_size);
		uint64_t after = now_ns();

		fault_latencies[i] = after - before;
	}

	ru_after = rusage_snap();
	t_faults = now_ns();

	t_end = t_faults;

	/* Verify */
	unsigned char expect = write_mode ? FILL_BYTE : 0;
	int errors = 0;

	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;

		if (p[0] != expect) {
			errors++;
			if (errors <= 3)
				fprintf(stderr, "  page %zu: got 0x%02x "
					"expected 0x%02x\n",
					i, p[0], expect);
		}
	}
	if (errors)
		fprintf(stderr, "  VERIFICATION FAILED: %d pages wrong\n",
			errors);
	else
		printf("  Verification: OK\n");

	rd = rusage_diff(&ru_before, &ru_after);
	print_results("baseline", num_pages, t_start, t_setup,
		      t_faults, t_end, &rd, fault_latencies, num_pages, 0);

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
	int      write_mode;	/* 0 = ZEROPAGE, 1 = COPY */
};

static void *uffd_handler_thread(void *arg)
{
	struct uffd_handler_args *ha = arg;
	char *src_page = NULL;
	ssize_t nread;

	if (ha->write_mode) {
		src_page = mmap(NULL, ha->page_size, PROT_READ | PROT_WRITE,
				MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (src_page == MAP_FAILED) {
			perror("mmap src_page");
			return NULL;
		}
		memset(src_page, FILL_BYTE, ha->page_size);
	}

	for (;;) {
		struct uffd_msg msg;
		struct pollfd pfd = {
			.fd     = ha->uffd,
			.events = POLLIN,
		};
		unsigned long addr;

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

		addr = msg.arg.pagefault.address & ~(ha->page_size - 1);

		if (ha->write_mode) {
			struct uffdio_copy uc = {
				.dst  = addr,
				.src  = (unsigned long)src_page,
				.len  = ha->page_size,
				.mode = 0,
			};

			if (ioctl(ha->uffd, UFFDIO_COPY, &uc) < 0) {
				if (errno != EEXIST)
					perror("UFFDIO_COPY");
			}
		} else {
			struct uffdio_zeropage uz = {
				.range.start = addr,
				.range.len   = ha->page_size,
				.mode        = 0,
			};

			if (ioctl(ha->uffd, UFFDIO_ZEROPAGE, &uz) < 0) {
				if (errno != EEXIST)
					perror("UFFDIO_ZEROPAGE");
			}
		}
	}

	if (src_page)
		munmap(src_page, ha->page_size);
	return NULL;
}

static void bench_userfaultfd(size_t num_pages, size_t page_size,
			      int write_mode)
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

	printf("=== userfaultfd benchmark (%s) ===\n",
	       write_mode ? "UFFDIO_COPY" : "UFFDIO_ZEROPAGE");
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
		.uffd       = uffd,
		.page_size  = page_size,
		.num_pages  = num_pages,
		.region     = region,
		.done       = 0,
		.write_mode = write_mode,
	};
	pthread_create(&handler, NULL, uffd_handler_thread, &ha);

	t_setup = now_ns();

	/* Fault phase: read each page sequentially */
	ru_before = rusage_snap();

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		char c = *p;
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
	unsigned char expect = write_mode ? FILL_BYTE : 0;
	int errors = 0;

	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;

		if (p[0] != expect) {
			errors++;
			if (errors <= 3)
				fprintf(stderr, "  page %zu: got 0x%02x "
					"expected 0x%02x\n",
					i, p[0], expect);
		}
	}
	if (errors)
		fprintf(stderr, "  VERIFICATION FAILED: %d pages wrong\n",
			errors);
	else
		printf("  Verification: OK\n");

	rd = rusage_diff(&ru_before, &ru_after);
	print_results("userfaultfd", num_pages, t_start, t_setup,
		      t_faults, t_end, &rd, fault_latencies, num_pages, 0);

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

static void bench_bpf_fault(size_t num_pages, size_t page_size,
			    int write_mode)
{
	size_t region_size = num_pages * page_size;
	void *region;
	struct fault_ops_bpf *skel;
	struct bpf_link *link;
	uint64_t t_start, t_setup, t_faults, t_teardown, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== bpf_fault benchmark (%s) ===\n",
	       write_mode ? "fill page" : "zero page");
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
		goto out_unmap;
	}

	fprintf(stderr, "  [dbg] opening BPF skeleton...\n");
	fflush(stderr);
	skel = fault_ops_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		goto out_unmap;
	}

	/* Control whether the BPF handler fills the page */
	skel->rodata->fill_page = write_mode ? 1 : 0;

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

	/* Fault phase: read each page sequentially */
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
	unsigned char expect = write_mode ? FILL_BYTE : 0;
	int errors = 0;

	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;

		if (p[0] != expect) {
			errors++;
			if (errors <= 3)
				printf("  page %zu: got 0x%02x expected "
				       "0x%02x\n", i, p[0], expect);
		}
	}
	if (errors)
		printf("  VERIFICATION FAILED: %d pages wrong\n", errors);
	else
		printf("  Verification: OK\n");

	rd = rusage_diff(&ru_before, &ru_after);
	print_results("bpf_fault", num_pages, t_start, t_setup,
		      t_faults, t_end, &rd, fault_latencies, num_pages, 0);

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
/*  SIGSEGV + mprotect benchmark                                       */
/* ------------------------------------------------------------------ */

static long sig_page_size;
static volatile size_t sig_fault_count;
static volatile int sig_write_mode;

static void sigsegv_handler(int sig, siginfo_t *si, void *ctx)
{
	unsigned long addr = (unsigned long)si->si_addr;
	unsigned long page = addr & ~(sig_page_size - 1);

	if (mprotect((void *)page, sig_page_size, PROT_READ | PROT_WRITE) < 0)
		_exit(1);

	if (sig_write_mode)
		memset((void *)page, FILL_BYTE, sig_page_size);

	sig_fault_count++;
}

static void bench_sigsegv(size_t num_pages, size_t page_size, int write_mode)
{
	size_t region_size = num_pages * page_size;
	void *region;
	struct sigaction sa, old_sa;
	uint64_t t_start, t_setup, t_faults, t_teardown, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== SIGSEGV+mprotect benchmark (%s) ===\n",
	       write_mode ? "mprotect+memset" : "mprotect only");
	printf("  Pages: %zu  Page size: %zu  Region: %zu bytes\n",
	       num_pages, page_size, region_size);
	fflush(stdout);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	region = mmap(NULL, region_size, PROT_NONE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		free(fault_latencies);
		return;
	}

	/* Install SIGSEGV handler */
	sig_page_size = page_size;
	sig_fault_count = 0;
	sig_write_mode = write_mode;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigsegv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSEGV, &sa, &old_sa) < 0) {
		perror("sigaction");
		munmap(region, region_size);
		free(fault_latencies);
		return;
	}

	t_setup = now_ns();

	/* Fault phase: read each page — triggers SIGSEGV */
	ru_before = rusage_snap();

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		char c = *p;
		uint64_t after = now_ns();

		fault_latencies[i] = after - before;
		(void)c;
	}

	ru_after = rusage_snap();
	t_faults = now_ns();

	/* Teardown — restore default handler */
	sigaction(SIGSEGV, &old_sa, NULL);

	t_teardown = now_ns();
	t_end = t_teardown;

	/* Verify */
	unsigned char expect = write_mode ? FILL_BYTE : 0;
	int errors = 0;

	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;

		if (p[0] != expect) {
			errors++;
			if (errors <= 3)
				fprintf(stderr, "  page %zu: got 0x%02x "
					"expected 0x%02x\n",
					i, p[0], expect);
		}
	}
	if (errors)
		fprintf(stderr, "  VERIFICATION FAILED: %d pages wrong\n",
			errors);
	else
		printf("  Verification: OK  (handler ran %zu times)\n",
		       sig_fault_count);

	rd = rusage_diff(&ru_before, &ru_after);
	print_results("sigsegv", num_pages, t_start, t_setup,
		      t_faults, t_end, &rd, fault_latencies, num_pages,
		      sig_fault_count);

	munmap(region, region_size);
	free(fault_latencies);
}

/* ------------------------------------------------------------------ */
/*  Main: run selected benchmarks                                      */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-n num_pages] [-r rounds] "
		"[-b uffd|bpf|sigsegv|baseline|all] [-W]\n",
		prog);
	fprintf(stderr, "  -n  Number of pages to fault (default: 1024)\n");
	fprintf(stderr, "  -r  Number of rounds (default: 3)\n");
	fprintf(stderr, "  -b  Which benchmark: uffd, bpf, sigsegv, "
		"baseline, or all (default: all)\n");
	fprintf(stderr, "  -W  Write/copy mode (default: read/zero mode)\n");
}

int main(int argc, char **argv)
{
	size_t num_pages = 1024;
	int rounds = 3;
	int do_baseline = 1, do_uffd = 1, do_bpf = 1, do_sigsegv = 1;
	int write_mode = 0;
	long page_size = sysconf(_SC_PAGESIZE);
	int opt;

	while ((opt = getopt(argc, argv, "n:r:b:Wh")) != -1) {
		switch (opt) {
		case 'n':
			num_pages = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			rounds = atoi(optarg);
			break;
		case 'b':
			do_baseline = 0;
			do_uffd = 0;
			do_bpf = 0;
			do_sigsegv = 0;
			if (strcmp(optarg, "uffd") == 0) {
				do_uffd = 1;
			} else if (strcmp(optarg, "bpf") == 0) {
				do_bpf = 1;
			} else if (strcmp(optarg, "sigsegv") == 0) {
				do_sigsegv = 1;
			} else if (strcmp(optarg, "baseline") == 0) {
				do_baseline = 1;
			} else if (strcmp(optarg, "all") == 0) {
				do_baseline = 1;
				do_uffd = 1;
				do_bpf = 1;
				do_sigsegv = 1;
			} else {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'W':
			write_mode = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	printf("Page fault benchmark: %zu pages (%zu bytes), %d rounds, "
	       "%s mode\n\n",
	       num_pages, num_pages * page_size, rounds,
	       write_mode ? "write/copy" : "read/zero");

	for (int r = 0; r < rounds; r++) {
		printf("--- Round %d/%d ---\n\n", r + 1, rounds);

		if (do_baseline)
			bench_baseline(num_pages, page_size, write_mode);
		if (do_uffd)
			bench_userfaultfd(num_pages, page_size, write_mode);
		if (do_sigsegv)
			bench_sigsegv(num_pages, page_size, write_mode);
		if (do_bpf)
			bench_bpf_fault(num_pages, page_size, write_mode);
	}

	return 0;
}
