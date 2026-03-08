// SPDX-License-Identifier: GPL-2.0-only
/*
 * Benchmark: baseline vs bpf_fault on file-backed MAP_PRIVATE mappings.
 *
 * Creates a file on a real filesystem (ext4/xfs/etc.), then measures the
 * cost of faulting in those pages under two scenarios:
 *
 *   baseline  - kernel maps page cache pages directly (COW on write)
 *   bpf       - bpf_fault intercepts each fault via the filemap_fault
 *               path, pre-populates the page from the page cache, lets
 *               the BPF program modify it, and installs a private copy
 *
 * Run with -c to test with a warm page cache (cached), or -d to drop
 * caches first (cold / disk-backed).  Default is cached.
 *
 * The file is written with 'X' (0x58).  The BPF program overwrites each
 * page with 'A' (0x41).  Verification checks:
 *   baseline: pages contain 'X' (original file data)
 *   bpf:      pages contain 'A' (BPF program output)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fault_ops.skel.h"
#include "bench_fault_util.h"

static uint64_t *fault_latencies;

#define FILE_BYTE   'X'

/* ------------------------------------------------------------------ */
/*  file helpers                                                        */
/* ------------------------------------------------------------------ */

static int create_test_file(const char *path, size_t num_pages,
			    size_t page_size)
{
	char *buf;
	int fd;

	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	buf = malloc(page_size);
	if (!buf) {
		close(fd);
		return -1;
	}
	memset(buf, FILE_BYTE, page_size);

	for (size_t i = 0; i < num_pages; i++) {
		if (write(fd, buf, page_size) != (ssize_t)page_size) {
			perror("write");
			free(buf);
			close(fd);
			return -1;
		}
	}

	fsync(fd);
	free(buf);
	return fd;
}

static void warm_cache(int fd, size_t region_size)
{
	void *m = mmap(NULL, region_size, PROT_READ,
		       MAP_PRIVATE | MAP_POPULATE, fd, 0);
	if (m != MAP_FAILED)
		munmap(m, region_size);
}

static void drop_cache(int fd, size_t region_size)
{
	posix_fadvise(fd, 0, region_size, POSIX_FADV_DONTNEED);
}

/* ------------------------------------------------------------------ */
/*  baseline benchmark: MAP_PRIVATE file, no interception                */
/* ------------------------------------------------------------------ */

static void bench_baseline(int fd, size_t num_pages, size_t page_size,
			   int cold)
{
	size_t region_size = num_pages * page_size;
	void *region;
	uint64_t t_start, t_setup, t_faults, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;
	int errors = 0;

	printf("=== file baseline (%s) ===\n", cold ? "cold" : "cached");
	printf("  Pages: %zu  Page size: %zu  Region: %zu bytes\n",
	       num_pages, page_size, region_size);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	if (cold)
		drop_cache(fd, region_size);
	else
		warm_cache(fd, region_size);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE, fd, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		free(fault_latencies);
		return;
	}

	t_setup = now_ns();

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
	t_end = t_faults;

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
	printf("  Verification: %s\n", errors ? "FAIL" : "OK");

	rd = rusage_diff(&ru_before, &ru_after);
	print_results("baseline", num_pages, t_start, t_setup,
		      t_faults, t_end, &rd, fault_latencies, num_pages, 0);

	munmap(region, region_size);
	free(fault_latencies);
}

/* ------------------------------------------------------------------ */
/*  bpf_fault benchmark: MAP_PRIVATE file with bpf_fault                 */
/* ------------------------------------------------------------------ */

static void bench_bpf_fault(int fd, size_t num_pages, size_t page_size,
			    int cold)
{
	size_t region_size = num_pages * page_size;
	void *region;
	struct fault_ops_bpf *skel;
	struct bpf_link *link;
	uint64_t t_start, t_setup, t_faults, t_teardown, t_end;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;
	int errors = 0;

	printf("=== file bpf_fault (%s) ===\n", cold ? "cold" : "cached");
	printf("  Pages: %zu  Page size: %zu  Region: %zu bytes\n",
	       num_pages, page_size, region_size);
	fflush(stdout);

	fault_latencies = calloc(num_pages, sizeof(uint64_t));

	t_start = now_ns();

	if (cold)
		drop_cache(fd, region_size);
	else
		warm_cache(fd, region_size);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE, fd, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
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

	bpf_link__destroy(link);
	fault_ops_bpf__destroy(skel);
	skel = NULL;

	t_teardown = now_ns();
	t_end = t_teardown;

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
	printf("  Verification: %s\n", errors ? "FAIL" : "OK");

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
/*  Main                                                                */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-n num_pages] [-r rounds] [-b baseline|bpf|all] [-c|-d] [-f path]\n",
		prog);
	fprintf(stderr, "  -n  Number of pages to fault (default: 1024)\n");
	fprintf(stderr, "  -r  Number of rounds (default: 3)\n");
	fprintf(stderr, "  -b  Which benchmark: baseline, bpf, or all (default: all)\n");
	fprintf(stderr, "  -c  Warm page cache before faulting (default)\n");
	fprintf(stderr, "  -d  Drop page cache before faulting (cold/disk)\n");
	fprintf(stderr, "  -f  Path for test file (default: .bench_fault_file_test)\n");
}

int main(int argc, char **argv)
{
	size_t num_pages = 1024;
	int rounds = 3;
	int do_baseline = 1, do_bpf = 1;
	int cold = 0;
	const char *filepath = ".bench_fault_file_test";
	long page_size = sysconf(_SC_PAGESIZE);
	int opt, fd;

	while ((opt = getopt(argc, argv, "n:r:b:cdf:h")) != -1) {
		switch (opt) {
		case 'n':
			num_pages = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			rounds = atoi(optarg);
			break;
		case 'b':
			if (strcmp(optarg, "bpf") == 0) {
				do_baseline = 0;
			} else if (strcmp(optarg, "baseline") == 0) {
				do_bpf = 0;
			} else if (strcmp(optarg, "all") != 0) {
				usage(argv[0]);
				return 1;
			}
			break;
		case 'c':
			cold = 0;
			break;
		case 'd':
			cold = 1;
			break;
		case 'f':
			filepath = optarg;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	printf("File-backed page fault benchmark: %zu pages (%zu bytes), %d rounds, %s\n\n",
	       num_pages, num_pages * page_size, rounds,
	       cold ? "cold (disk)" : "cached");

	fd = create_test_file(filepath, num_pages, page_size);
	if (fd < 0)
		return 1;

	for (int r = 0; r < rounds; r++) {
		printf("--- Round %d/%d ---\n\n", r + 1, rounds);

		if (do_baseline)
			bench_baseline(fd, num_pages, page_size, cold);
		if (do_bpf)
			bench_bpf_fault(fd, num_pages, page_size, cold);
	}

	close(fd);
	unlink(filepath);
	return 0;
}
