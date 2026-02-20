// SPDX-License-Identifier: GPL-2.0-only
/*
 * Benchmark: baseline vs userfaultfd vs bpf_fault on shmem/tmpfs mappings.
 *
 * Creates a tmpfs file pre-populated with data, then measures the cost of
 * faulting in those pages under three scenarios:
 *
 *   baseline  - kernel maps page cache pages directly (no interception)
 *   uffd      - userfaultfd MINOR mode intercepts each fault; the handler
 *               thread responds with UFFDIO_CONTINUE to map the existing
 *               page cache page (MAP_SHARED required for minor faults)
 *   bpf       - bpf_fault intercepts each fault, pre-populates the page
 *               from the page cache, lets the BPF program modify it, and
 *               installs a private COW copy (MAP_PRIVATE)
 *
 * The file is written with 'X' (0x58).  The BPF program overwrites each
 * page with 'A' (0x41).  Verification checks:
 *   baseline: pages contain 'X' (original file data)
 *   uffd:     pages contain 'X' (UFFDIO_CONTINUE maps existing page)
 *   bpf:      pages contain 'A' (BPF program output)
 *
 * Note: uffd uses MAP_SHARED (required for UFFD_REGISTER_MODE_MINOR on
 * shmem), while bpf uses MAP_PRIVATE.  The baseline runs both for
 * reference, but only the MAP_SHARED variant is directly comparable to uffd.
 *
 * Metrics: wall-clock time, setup/fault/teardown breakdown, per-fault
 * latency (avg, min, max, p50, p99, p999), context switches, page faults.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fault_ops.skel.h"
#include "bench_fault_util.h"

static uint64_t *fault_latencies;

#define FILE_BYTE   'X'   /* file pre-populated with this */

/* ------------------------------------------------------------------ */
/*  tmpfs file helpers                                                  */
/* ------------------------------------------------------------------ */

/*
 * Create a tmpfs file filled with FILE_BYTE.  Returns fd on success.
 * The file is unlinked immediately so it disappears on close.
 */
static int create_tmpfs_file(size_t num_pages, size_t page_size)
{
	char path[256];
	char *buf;
	int fd;

	snprintf(path, sizeof(path), "%s/bench_fault_shmem.XXXXXX",
		 find_tmpfs());
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		return -1;
	}
	unlink(path);

	buf = malloc(page_size);
	if (!buf) {
		close(fd);
		return -1;
	}
	memset(buf, FILE_BYTE, page_size);

	for (size_t i = 0; i < num_pages; i++) {
		if (write(fd, buf, page_size) != (ssize_t)page_size) {
			perror("write tmpfs file");
			free(buf);
			close(fd);
			return -1;
		}
	}

	free(buf);
	return fd;
}

/* ------------------------------------------------------------------ */
/*  baseline benchmark: MAP_PRIVATE shmem, no interception              */
/* ------------------------------------------------------------------ */

static void bench_baseline(size_t num_pages, size_t page_size)
{
	size_t region_size = num_pages * page_size;
	void *region;
	int fd;
	uint64_t t_start, t_setup, t_faults, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== shmem baseline benchmark (no bpf) ===\n");
	printf("  Pages: %zu  Page size: %zu  Region: %zu bytes\n",
	       num_pages, page_size, region_size);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	fd = create_tmpfs_file(num_pages, page_size);
	if (fd < 0) {
		free(fault_latencies);
		return;
	}

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE, fd, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		close(fd);
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

	/* Verify: should see original file data */
	int errors = 0;

	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;

		if (p[0] != FILE_BYTE) {
			errors++;
			if (errors <= 3)
				fprintf(stderr,
					"  page %zu: got 0x%02x expected 0x%02x\n",
					i, p[0], FILE_BYTE);
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
	close(fd);
	free(fault_latencies);
}

/* ------------------------------------------------------------------ */
/*  userfaultfd benchmark: MAP_SHARED shmem with MINOR fault mode       */
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
	ssize_t nread;

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

		/*
		 * MINOR fault: the page already exists in the page cache.
		 * UFFDIO_CONTINUE maps it into the process's page table.
		 */
		struct uffdio_continue cont = {
			.range = {
				.start = msg.arg.pagefault.address &
					 ~(ha->page_size - 1),
				.len   = ha->page_size,
			},
			.mode = 0,
		};

		if (ioctl(ha->uffd, UFFDIO_CONTINUE, &cont) < 0) {
			if (errno != EEXIST)
				perror("UFFDIO_CONTINUE");
		}
	}

	return NULL;
}

static void bench_userfaultfd(size_t num_pages, size_t page_size)
{
	size_t region_size = num_pages * page_size;
	void *region;
	int fd, uffd;
	struct uffdio_api api;
	struct uffdio_register reg;
	pthread_t handler;
	struct uffd_handler_args ha;
	uint64_t t_start, t_setup, t_faults, t_teardown, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== shmem userfaultfd benchmark (MINOR mode) ===\n");
	printf("  Pages: %zu  Page size: %zu  Region: %zu bytes\n",
	       num_pages, page_size, region_size);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	fd = create_tmpfs_file(num_pages, page_size);
	if (fd < 0) {
		free(fault_latencies);
		return;
	}

	/*
	 * UFFD_REGISTER_MODE_MINOR on shmem requires MAP_SHARED so
	 * that faults hit the page cache path (not anonymous COW).
	 */
	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED, fd, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		close(fd);
		free(fault_latencies);
		return;
	}

	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0) {
		perror("userfaultfd");
		goto out_unmap_uffd;
	}

	api.api = UFFD_API;
	api.features = UFFD_FEATURE_MINOR_SHMEM;
	if (ioctl(uffd, UFFDIO_API, &api) < 0) {
		perror("UFFDIO_API");
		goto out_close;
	}

	reg.range.start = (unsigned long)region;
	reg.range.len   = region_size;
	reg.mode        = UFFDIO_REGISTER_MODE_MINOR;
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
		char c = *p;  /* trigger the minor fault */
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

	/* Verify: UFFDIO_CONTINUE maps existing page, should see FILE_BYTE */
	int errors = 0;

	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;

		if (p[0] != FILE_BYTE) {
			errors++;
			if (errors <= 3)
				fprintf(stderr,
					"  page %zu: got 0x%02x expected 0x%02x\n",
					i, p[0], FILE_BYTE);
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
	close(fd);
	free(fault_latencies);
	return;

out_close:
	close(uffd);
out_unmap_uffd:
	munmap(region, region_size);
	close(fd);
	free(fault_latencies);
}

/* ------------------------------------------------------------------ */
/*  bpf_fault benchmark: MAP_PRIVATE shmem with bpf_fault               */
/* ------------------------------------------------------------------ */

static void bench_bpf_fault(size_t num_pages, size_t page_size)
{
	size_t region_size = num_pages * page_size;
	void *region;
	int fd;
	struct fault_ops_bpf *skel;
	struct bpf_link *link;
	uint64_t t_start, t_setup, t_faults, t_teardown, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;

	printf("=== shmem bpf_fault benchmark ===\n");
	printf("  Pages: %zu  Page size: %zu  Region: %zu bytes\n",
	       num_pages, page_size, region_size);
	fflush(stdout);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	fd = create_tmpfs_file(num_pages, page_size);
	if (fd < 0) {
		free(fault_latencies);
		return;
	}

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE, fd, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		close(fd);
		free(fault_latencies);
		return;
	}

	skel = fault_ops_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		goto out_unmap;
	}

	if (fault_ops_bpf__load(skel)) {
		fprintf(stderr, "Failed to load BPF program: %s\n",
			strerror(errno));
		goto out_destroy;
	}

	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out_destroy;
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

	/* Teardown */
	bpf_link__destroy(link);
	fault_ops_bpf__destroy(skel);
	skel = NULL;

	t_teardown = now_ns();
	t_end = t_teardown;

	/* Verify: BPF program should have filled with FILL_BYTE */
	int errors = 0;

	for (size_t i = 0; i < num_pages; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;

		if (p[0] != FILL_BYTE) {
			errors++;
			if (errors <= 3)
				fprintf(stderr,
					"  page %zu: got 0x%02x expected 0x%02x\n",
					i, p[0], FILL_BYTE);
		}
	}
	if (errors)
		fprintf(stderr, "  VERIFICATION FAILED: %d pages wrong\n",
			errors);
	else
		printf("  Verification: OK\n");

	rd = rusage_diff(&ru_before, &ru_after);
	print_results("bpf_fault", num_pages, t_start, t_setup,
		      t_faults, t_end, &rd, fault_latencies, num_pages, 0);

	munmap(region, region_size);
	close(fd);
	free(fault_latencies);
	return;

out_destroy:
	fault_ops_bpf__destroy(skel);
out_unmap:
	munmap(region, region_size);
	close(fd);
	free(fault_latencies);
}

/* ------------------------------------------------------------------ */
/*  Main                                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-n num_pages] [-r rounds] [-b baseline|uffd|bpf|all]\n",
		prog);
	fprintf(stderr, "  -n  Number of pages to fault (default: 1024)\n");
	fprintf(stderr, "  -r  Number of rounds (default: 3)\n");
	fprintf(stderr, "  -b  Which benchmark: baseline, uffd, bpf, or all (default: all)\n");
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

	printf("Shmem page fault benchmark: %zu pages (%zu bytes), %d rounds\n\n",
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
