// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test: bpf_fault on MAP_PRIVATE shmem/tmpfs mappings.
 *
 * Verifies that bpf_fault correctly intercepts page faults on tmpfs
 * file-backed MAP_PRIVATE mappings for two cases:
 *
 *   1. Pages that already have contents in the page cache (the BPF
 *      program should see the original file data pre-populated).
 *   2. Holes (pages never written — the BPF program sees zeros).
 *
 * The BPF program (fault_ops.bpf.c) fills every page with 'A' (0x41).
 * After faulting, we verify all pages contain 'A' regardless of whether
 * the page cache had data or not.
 *
 * Additionally tests that VM_SHARED shmem is correctly rejected.
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

#define FILL_BYTE 'A'

static long page_size;

static int check_page(const void *region, size_t page_idx,
		      unsigned char expected)
{
	const unsigned char *p = (const unsigned char *)region +
				 page_idx * page_size;

	for (long i = 0; i < page_size; i++) {
		if (p[i] != expected) {
			fprintf(stderr,
				"    FAIL: page %zu offset %ld: got 0x%02x expected 0x%02x\n",
				page_idx, i, p[i], expected);
			return -1;
		}
	}
	return 0;
}

/*
 * Find a writable tmpfs mount point.  Prefer /dev/shm, fall back to /tmp.
 */
static const char *find_tmpfs(void)
{
	struct stat st;

	if (stat("/dev/shm", &st) == 0)
		return "/dev/shm";
	return "/tmp";
}

/*
 * Test 1: bpf_fault on pages that exist in the page cache.
 *
 * Write 'X' into a tmpfs file, mmap MAP_PRIVATE, attach bpf_fault,
 * fault on each page.  The BPF program should see 'X' pre-populated
 * and overwrite with 'A'.
 */
static int test_cached_pages(void)
{
	const size_t num_pages = 16;
	const size_t region_size = num_pages * page_size;
	char path[256];
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: cached pages ... ");
	fflush(stdout);

	snprintf(path, sizeof(path), "%s/bpf_fault_test_cached.XXXXXX",
		 find_tmpfs());
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		goto out;
	}

	/* Fill the file with 'X' */
	for (size_t i = 0; i < num_pages; i++) {
		char buf[4096];

		memset(buf, 'X', sizeof(buf));
		if (write(fd, buf, page_size) != page_size) {
			perror("write");
			goto out;
		}
	}

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE, fd, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	/* Fault on each page */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		char c = *p;
		(void)c;
	}

	/* Verify: BPF program should have filled with 'A' */
	ret = 0;
	for (size_t i = 0; i < num_pages; i++) {
		if (check_page(region, i, FILL_BYTE)) {
			ret = -1;
			break;
		}
	}

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);
	if (fd >= 0) {
		close(fd);
		unlink(path);
	}

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

/*
 * Test 2: bpf_fault on holes (pages not in the page cache).
 *
 * Create a file sized to num_pages but only write data into the first
 * half.  Fault on the second half (holes).  The BPF program starts
 * from a zeroed page and fills with 'A'.
 */
static int test_hole_pages(void)
{
	const size_t num_pages = 16;
	const size_t written_pages = num_pages / 2;
	const size_t region_size = num_pages * page_size;
	char path[256];
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: hole pages ... ");
	fflush(stdout);

	snprintf(path, sizeof(path), "%s/bpf_fault_test_hole.XXXXXX",
		 find_tmpfs());
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		goto out;
	}

	/* Write only the first half */
	for (size_t i = 0; i < written_pages; i++) {
		char buf[4096];

		memset(buf, 'X', sizeof(buf));
		if (write(fd, buf, page_size) != page_size) {
			perror("write");
			goto out;
		}
	}

	/* Extend the file to cover the hole region */
	if (ftruncate(fd, region_size) < 0) {
		perror("ftruncate");
		goto out;
	}

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE, fd, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	/* Fault only on the hole pages (second half) */
	for (size_t i = written_pages; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		char c = *p;
		(void)c;
	}

	/* Verify: hole pages should be filled with 'A' by BPF program */
	ret = 0;
	for (size_t i = written_pages; i < num_pages; i++) {
		if (check_page(region, i, FILL_BYTE)) {
			ret = -1;
			break;
		}
	}

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);
	if (fd >= 0) {
		close(fd);
		unlink(path);
	}

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

/*
 * Test 3: VM_SHARED shmem should be rejected.
 */
static int test_shared_rejected(void)
{
	const size_t num_pages = 4;
	const size_t region_size = num_pages * page_size;
	char path[256];
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: shared shmem rejected ... ");
	fflush(stdout);

	snprintf(path, sizeof(path), "%s/bpf_fault_test_shared.XXXXXX",
		 find_tmpfs());
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		goto out;
	}

	if (ftruncate(fd, region_size) < 0) {
		perror("ftruncate");
		goto out;
	}

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_SHARED, fd, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 region, region_size, 0);
	if (link) {
		fprintf(stderr, "attach should have failed for VM_SHARED\n");
		bpf_link__destroy(link);
		link = NULL;
		goto out;
	}

	/* Expected: attach fails with EINVAL */
	if (errno == EINVAL) {
		ret = 0;
	} else {
		fprintf(stderr, "expected EINVAL, got %s\n", strerror(errno));
	}

out:
	if (skel)
		fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);
	if (fd >= 0) {
		close(fd);
		unlink(path);
	}

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

/*
 * Test 4: mixed — file with cached pages and holes, fault all pages.
 */
static int test_mixed(void)
{
	const size_t num_pages = 16;
	const size_t written_pages = num_pages / 2;
	const size_t region_size = num_pages * page_size;
	char path[256];
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: mixed cached + hole pages ... ");
	fflush(stdout);

	snprintf(path, sizeof(path), "%s/bpf_fault_test_mixed.XXXXXX",
		 find_tmpfs());
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		goto out;
	}

	/* Write first half with data, leave second half as holes */
	for (size_t i = 0; i < written_pages; i++) {
		char buf[4096];

		memset(buf, 'X', sizeof(buf));
		if (write(fd, buf, page_size) != page_size) {
			perror("write");
			goto out;
		}
	}

	if (ftruncate(fd, region_size) < 0) {
		perror("ftruncate");
		goto out;
	}

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE, fd, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	/* Fault ALL pages — both cached and holes */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		char c = *p;
		(void)c;
	}

	/* All pages should contain 'A' from BPF program */
	ret = 0;
	for (size_t i = 0; i < num_pages; i++) {
		if (check_page(region, i, FILL_BYTE)) {
			fprintf(stderr, "    (page %zu is %s)\n", i,
				i < written_pages ? "cached" : "hole");
			ret = -1;
			break;
		}
	}

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);
	if (fd >= 0) {
		close(fd);
		unlink(path);
	}

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

int main(void)
{
	int failures = 0;

	page_size = sysconf(_SC_PAGESIZE);

	printf("=== bpf_fault shmem tests ===\n");

	if (test_cached_pages())
		failures++;
	if (test_hole_pages())
		failures++;
	if (test_shared_rejected())
		failures++;
	if (test_mixed())
		failures++;

	printf("\n%d/%d tests passed\n",
	       4 - failures, 4);

	return failures ? 1 : 0;
}
