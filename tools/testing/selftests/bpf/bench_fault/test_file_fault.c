// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test: bpf_fault on file-backed MAP_PRIVATE mappings.
 *
 * Verifies that bpf_fault correctly intercepts page faults on regular
 * file-backed (ext4, xfs, etc.) MAP_PRIVATE mappings.  The BPF program
 * (fault_ops.bpf.c) fills every page with 'A' (0x41).
 *
 * Tests:
 *   1. Cached pages — file data already in page cache, BPF overwrites.
 *   2. Cold pages — drop caches first, BPF sees data read from disk.
 *   3. Mixed — some pages cached, some cold.
 *   4. Shared file-backed rejected — VM_SHARED should fail registration.
 *   5. Detach restores normal faults — after detach, reads see file data.
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
#include "sigbus_util.h"
#include "bench_fault_util.h"

static long page_size;

/*
 * Helper: create a temporary file in the current directory (which should
 * be a real filesystem, not tmpfs) and fill it with a per-page pattern.
 *
 * Each page is filled with (page_index & 0xff) so we can verify later
 * that the kernel read the correct data.
 */
static int create_test_file(const char *path, size_t num_pages,
			    unsigned char fill)
{
	char buf[4096];
	int fd;

	fd = open(path, O_CREAT | O_RDWR | O_TRUNC, 0600);
	if (fd < 0) {
		perror("open");
		return -1;
	}

	for (size_t i = 0; i < num_pages; i++) {
		unsigned char c = fill ? fill : (unsigned char)(i & 0xff);

		memset(buf, c, page_size);
		if (write(fd, buf, page_size) != page_size) {
			perror("write");
			close(fd);
			unlink(path);
			return -1;
		}
	}

	/* Flush to disk so posix_fadvise DONTNEED actually works */
	fsync(fd);
	return fd;
}

static void drop_page_cache(int fd, size_t len)
{
	posix_fadvise(fd, 0, len, POSIX_FADV_DONTNEED);
}

/*
 * Test 1: bpf_fault on file pages already in page cache.
 *
 * Write data to file, mmap MAP_PRIVATE, read to populate cache,
 * then unmap, re-mmap with bpf_fault, and verify BPF program runs.
 */
static int test_cached_pages(void)
{
	const size_t num_pages = 16;
	const size_t region_size = num_pages * page_size;
	const char *path = ".bpf_fault_test_cached";
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: file-backed cached pages ... ");
	fflush(stdout);

	fd = create_test_file(path, num_pages, 'X');
	if (fd < 0)
		goto out;

	/* Warm the page cache by reading via a separate mapping */
	{
		void *warm = mmap(NULL, region_size, PROT_READ,
				  MAP_PRIVATE | MAP_POPULATE, fd, 0);
		if (warm != MAP_FAILED)
			munmap(warm, region_size);
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

	/* Fault each page */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		(void)*p;
	}

	/* Verify: BPF program should have filled with 'A' */
	ret = 0;
	for (size_t i = 0; i < num_pages; i++) {
		if (check_page(region, i, FILL_BYTE, page_size)) {
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
 * Test 2: bpf_fault on cold file pages (not in page cache).
 *
 * Write data to file, flush to disk, drop caches, then mmap with
 * bpf_fault.  The kernel must read from disk before BPF sees the data.
 */
static int test_cold_pages(void)
{
	const size_t num_pages = 16;
	const size_t region_size = num_pages * page_size;
	const char *path = ".bpf_fault_test_cold";
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: file-backed cold pages ... ");
	fflush(stdout);

	fd = create_test_file(path, num_pages, 'Y');
	if (fd < 0)
		goto out;

	/* Drop page cache — pages must be read from disk */
	drop_page_cache(fd, region_size);

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

	/* Fault each page — triggers I/O + BPF intercept */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		(void)*p;
	}

	/* Verify: BPF program fills with 'A' regardless of on-disk content */
	ret = 0;
	for (size_t i = 0; i < num_pages; i++) {
		if (check_page(region, i, FILL_BYTE, page_size)) {
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
 * Test 3: mixed — some pages cached, some cold.
 *
 * Write all pages, drop caches, then warm only the first half.
 * Fault all pages through bpf_fault and verify BPF program ran on all.
 */
static int test_mixed(void)
{
	const size_t num_pages = 16;
	const size_t warm_pages = num_pages / 2;
	const size_t region_size = num_pages * page_size;
	const char *path = ".bpf_fault_test_mixed";
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: file-backed mixed cached + cold ... ");
	fflush(stdout);

	fd = create_test_file(path, num_pages, 'Z');
	if (fd < 0)
		goto out;

	/* Drop all pages from cache */
	drop_page_cache(fd, region_size);

	/* Warm only the first half */
	{
		void *warm = mmap(NULL, warm_pages * page_size, PROT_READ,
				  MAP_PRIVATE | MAP_POPULATE, fd, 0);
		if (warm != MAP_FAILED)
			munmap(warm, warm_pages * page_size);
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

	/* Fault all pages */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		(void)*p;
	}

	/* All pages should contain 'A' from BPF program */
	ret = 0;
	for (size_t i = 0; i < num_pages; i++) {
		if (check_page(region, i, FILL_BYTE, page_size)) {
			fprintf(stderr, "    (page %zu is %s)\n", i,
				i < warm_pages ? "cached" : "cold");
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
 * Test 4: VM_SHARED file-backed should be rejected.
 */
static int test_shared_rejected(void)
{
	const size_t num_pages = 4;
	const size_t region_size = num_pages * page_size;
	const char *path = ".bpf_fault_test_shared";
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: shared file-backed rejected ... ");
	fflush(stdout);

	fd = create_test_file(path, num_pages, 'S');
	if (fd < 0)
		goto out;

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
 * Test 5: detach restores normal MAP_PRIVATE file faults.
 *
 * Attach bpf_fault, then detach without faulting.  Subsequent reads
 * should see the original file data, not BPF-filled data.
 */
static int test_normal_after_detach(void)
{
	const size_t num_pages = 4;
	const size_t region_size = num_pages * page_size;
	const char *path = ".bpf_fault_test_detach";
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: file-backed normal after detach ... ");
	fflush(stdout);

	fd = create_test_file(path, num_pages, 'D');
	if (fd < 0)
		goto out;

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

	/* Detach without faulting */
	bpf_link__destroy(link);
	link = NULL;

	/* Now faults should go through the normal file path */
	ret = 0;
	for (size_t i = 0; i < num_pages; i++) {
		if (check_page(region, i, 'D', page_size)) {
			fprintf(stderr,
				"    page %zu: expected 'D' (normal fault)\n",
				i);
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
	int total = 5;

	page_size = sysconf(_SC_PAGESIZE);

	printf("=== bpf_fault file-backed tests ===\n");

	if (test_cached_pages())
		failures++;
	if (test_cold_pages())
		failures++;
	if (test_mixed())
		failures++;
	if (test_shared_rejected())
		failures++;
	if (test_normal_after_detach())
		failures++;

	printf("\n%d/%d tests passed\n", total - failures, total);

	return failures ? 1 : 0;
}
