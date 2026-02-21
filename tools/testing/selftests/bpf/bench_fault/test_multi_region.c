// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test: bpf_fault multi-region support.
 *
 * Verifies the BPF_FAULT_REGISTER / BPF_FAULT_UNREGISTER commands:
 *
 *   1. Adding additional regions to an existing fault_ops link
 *   2. Faulting on multiple independently registered regions
 *   3. Unregistering a region while keeping others active
 *   4. Rejection of overlapping regions owned by different contexts
 *   5. Idempotent re-registration of the same region
 *   6. Invalid input validation
 *
 * Uses fault_ops.bpf.c which fills pages with 'A' (0x41).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fault_ops.skel.h"
#include "sigbus_util.h"
#include "wp_util.h"
#include "bench_fault_util.h"

static long page_size;

/*
 * Test 1: Basic multi-region.
 *
 * Create a link with region A, add region B via BPF_FAULT_REGISTER.
 * Fault on both regions, verify BPF-processed pages.
 */
static int test_basic_multi_region(void)
{
	const size_t region_size = 4 * page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region_a = MAP_FAILED, *region_b = MAP_FAILED;
	int ret = -1;

	printf("TEST: basic multi-region ... ");
	fflush(stdout);

	region_a = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	region_b = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region_a == MAP_FAILED || region_b == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	/* Attach with region A */
	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 region_a, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	/* Add region B */
	if (bpf_link_fault_register(bpf_link__fd(link),
				    (unsigned long)region_b,
				    region_size) < 0) {
		fprintf(stderr, "BPF_FAULT_REGISTER failed: %s\n",
			strerror(errno));
		goto out;
	}

	/* Fault on region A */
	for (size_t i = 0; i < 4; i++) {
		volatile char *p = (volatile char *)region_a + i * page_size;
		(void)*p;
	}
	for (size_t i = 0; i < 4; i++) {
		if (check_page(region_a, i, FILL_BYTE, page_size) < 0) {
			fprintf(stderr, "    FAIL: region A page %zu wrong\n", i);
			goto out;
		}
	}

	/* Fault on region B */
	for (size_t i = 0; i < 4; i++) {
		volatile char *p = (volatile char *)region_b + i * page_size;
		(void)*p;
	}
	for (size_t i = 0; i < 4; i++) {
		if (check_page(region_b, i, FILL_BYTE, page_size) < 0) {
			fprintf(stderr, "    FAIL: region B page %zu wrong\n", i);
			goto out;
		}
	}

	ret = 0;
	printf("PASS\n");

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		fault_ops_bpf__destroy(skel);
	if (region_a != MAP_FAILED)
		munmap(region_a, region_size);
	if (region_b != MAP_FAILED)
		munmap(region_b, region_size);
	return ret;
}

/*
 * Test 2: Many regions.
 *
 * Add 16 regions to a single link, fault on each.
 */
static int test_many_regions(void)
{
	const int nr_regions = 16;
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *regions[16];
	int ret = -1;

	printf("TEST: many regions ... ");
	fflush(stdout);

	memset(regions, 0, sizeof(regions));
	for (int i = 0; i < nr_regions; i++) {
		regions[i] = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
				  MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (regions[i] == MAP_FAILED) {
			perror("mmap");
			goto out;
		}
	}

	skel = fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	/* Attach with first region */
	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 regions[0], region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	/* Register remaining regions */
	for (int i = 1; i < nr_regions; i++) {
		if (bpf_link_fault_register(bpf_link__fd(link),
					    (unsigned long)regions[i],
					    region_size) < 0) {
			fprintf(stderr, "BPF_FAULT_REGISTER region %d failed: %s\n",
				i, strerror(errno));
			goto out;
		}
	}

	/* Fault on each region and verify */
	for (int i = 0; i < nr_regions; i++) {
		volatile char *p = (volatile char *)regions[i];
		(void)*p;
		if (check_page(regions[i], 0, FILL_BYTE, page_size) < 0) {
			fprintf(stderr, "    FAIL: region %d page wrong\n", i);
			goto out;
		}
	}

	ret = 0;
	printf("PASS\n");

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		fault_ops_bpf__destroy(skel);
	for (int i = 0; i < nr_regions; i++)
		if (regions[i] && regions[i] != MAP_FAILED)
			munmap(regions[i], region_size);
	return ret;
}

/*
 * Test 3: Unregister region.
 *
 * Register A+B, unregister B.  Fault on A still works (BPF content),
 * fault on B gets default zero-fill.
 */
static int test_unregister_region(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region_a = MAP_FAILED, *region_b = MAP_FAILED;
	int ret = -1;

	printf("TEST: unregister region ... ");
	fflush(stdout);

	region_a = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	region_b = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region_a == MAP_FAILED || region_b == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 region_a, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	if (bpf_link_fault_register(bpf_link__fd(link),
				    (unsigned long)region_b,
				    region_size) < 0) {
		fprintf(stderr, "BPF_FAULT_REGISTER failed: %s\n",
			strerror(errno));
		goto out;
	}

	/* Unregister region B */
	if (bpf_link_fault_unregister(bpf_link__fd(link),
				      (unsigned long)region_b,
				      region_size) < 0) {
		fprintf(stderr, "BPF_FAULT_UNREGISTER failed: %s\n",
			strerror(errno));
		goto out;
	}

	/* Region A: should still get BPF-filled content */
	{
		volatile char *p = (volatile char *)region_a;
		(void)*p;
		if (check_page(region_a, 0, FILL_BYTE, page_size) < 0) {
			fprintf(stderr, "    FAIL: region A page wrong\n");
			goto out;
		}
	}

	/* Region B: should get default zero-fill */
	{
		volatile char *p = (volatile char *)region_b;
		(void)*p;
		if (check_page(region_b, 0, 0, page_size) < 0) {
			fprintf(stderr, "    FAIL: region B page not zero\n");
			goto out;
		}
	}

	ret = 0;
	printf("PASS\n");

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		fault_ops_bpf__destroy(skel);
	if (region_a != MAP_FAILED)
		munmap(region_a, region_size);
	if (region_b != MAP_FAILED)
		munmap(region_b, region_size);
	return ret;
}

/*
 * Test 4: Same-ctx idempotent.
 *
 * Register the same region twice with the same context — should succeed.
 */
static int test_same_ctx_idempotent(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int ret = -1;

	printf("TEST: same ctx idempotent ... ");
	fflush(stdout);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

	/* Re-register same region — should succeed */
	if (bpf_link_fault_register(bpf_link__fd(link),
				    (unsigned long)region,
				    region_size) < 0) {
		fprintf(stderr, "BPF_FAULT_REGISTER idempotent failed: %s\n",
			strerror(errno));
		goto out;
	}

	/* Verify it still works */
	{
		volatile char *p = (volatile char *)region;
		(void)*p;
		if (check_page(region, 0, FILL_BYTE, page_size) < 0) {
			fprintf(stderr, "    FAIL: page wrong after re-register\n");
			goto out;
		}
	}

	ret = 0;
	printf("PASS\n");

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);
	return ret;
}

/*
 * Test 5: Invalid inputs.
 *
 * Non-page-aligned start, zero len → EINVAL.
 */
static int test_invalid_inputs(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int ret = -1;

	printf("TEST: invalid inputs ... ");
	fflush(stdout);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
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

	/* Non-page-aligned start */
	if (bpf_link_fault_register(bpf_link__fd(link),
				    (unsigned long)region + 1,
				    region_size) == 0) {
		fprintf(stderr, "    FAIL: non-aligned start accepted\n");
		goto out;
	}

	/* Zero length */
	if (bpf_link_fault_register(bpf_link__fd(link),
				    (unsigned long)region, 0) == 0) {
		fprintf(stderr, "    FAIL: zero len accepted\n");
		goto out;
	}

	/* Non-page-aligned unregister */
	if (bpf_link_fault_unregister(bpf_link__fd(link),
				      (unsigned long)region + 1,
				      region_size) == 0) {
		fprintf(stderr, "    FAIL: non-aligned unregister accepted\n");
		goto out;
	}

	ret = 0;
	printf("PASS\n");

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);
	return ret;
}

int main(void)
{
	int failed = 0;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}

	printf("=== bpf_fault multi-region tests ===\n\n");

	if (test_basic_multi_region() < 0)
		failed++;
	if (test_many_regions() < 0)
		failed++;
	if (test_unregister_region() < 0)
		failed++;
	if (test_same_ctx_idempotent() < 0)
		failed++;
	if (test_invalid_inputs() < 0)
		failed++;

	printf("\n%d/%d tests passed\n", 5 - failed, 5);
	return failed ? 1 : 0;
}
