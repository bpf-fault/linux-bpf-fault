// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test: bpf_fault write-protect (WP) support.
 *
 * Verifies the WP fault path end-to-end:
 *
 *   1. WP-only registration (no missing fault interception)
 *   2. BPF_LINK_WRITEPROTECT syscall to protect/resolve pages
 *   3. WP faults dispatched to BPF handle_wp_fault callback
 *   4. Proper error handling for invalid operations
 *
 * Uses wp_fault_ops.bpf.c which provides:
 *   - handle_wp_fault: allows writes, counts invocations
 *   - handle_page_fault: fills pages with 'A' (0x41)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "wp_fault_ops.skel.h"
#include "sigbus_fault_ops.skel.h"

/*
 * UAPI constants for bpf_fault write-protect support.
 * Defined here until they propagate to system headers.
 */
#ifndef BPF_LINK_WRITEPROTECT
#define BPF_LINK_WRITEPROTECT	38
#endif
#ifndef BPF_FAULT_FLAG_WP
#define BPF_FAULT_FLAG_WP	(1U << 0)
#endif
#ifndef BPF_FAULT_WP_ENABLE
#define BPF_FAULT_WP_ENABLE	(1U << 0)
#endif

#define FILL_BYTE 'A'

static long page_size;
static sigjmp_buf jmp_env;
static volatile sig_atomic_t sigbus_received;
static volatile void *sigbus_addr;

/*
 * Wrapper for BPF_LINK_WRITEPROTECT syscall.
 * Uses a local struct to avoid dependency on the full union bpf_attr
 * which may not yet include link_writeprotect in installed headers.
 */
struct bpf_link_wp_attr {
	__u32		link_fd;
	__u32		flags;
	__u64		start;
	__u64		len;
} __attribute__((aligned(8)));

static int bpf_link_writeprotect(int link_fd, __u64 start, __u64 len,
				 __u32 flags)
{
	struct bpf_link_wp_attr attr;

	memset(&attr, 0, sizeof(attr));
	attr.link_fd = link_fd;
	attr.flags = flags;
	attr.start = start;
	attr.len = len;

	return syscall(__NR_bpf, BPF_LINK_WRITEPROTECT, &attr, sizeof(attr));
}

static void sigbus_handler(int sig, siginfo_t *si, void *ctx)
{
	(void)sig;
	(void)ctx;
	sigbus_received = 1;
	sigbus_addr = si->si_addr;
	siglongjmp(jmp_env, 1);
}

static int install_sigbus_handler(struct sigaction *old_sa)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigbus_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);

	if (sigaction(SIGBUS, &sa, old_sa) < 0) {
		perror("sigaction(SIGBUS)");
		return -1;
	}
	return 0;
}

static __u64 read_wp_count(struct wp_fault_ops_bpf *skel)
{
	return skel->bss->wp_fault_count;
}

static void reset_wp_count(struct wp_fault_ops_bpf *skel)
{
	skel->bss->wp_fault_count = 0;
}

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
 * Test 1: Basic WP fault handling.
 *
 * Register WP-only, populate pages, write-protect them, then write.
 * Each write triggers a WP fault handled by BPF (which allows it).
 * Verify: writes succeed, wp_fault_count matches page count.
 */
static int test_wp_basic(void)
{
	const size_t num_pages = 16;
	const size_t region_size = num_pages * page_size;
	struct wp_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int ret = -1;

	printf("TEST: wp basic ... ");
	fflush(stdout);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = wp_fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	/* Attach with WP flag */
	link = bpf_map__attach_fault_ops(skel->maps.wp_fault_ops,
					 region, region_size,
					 BPF_FAULT_FLAG_WP);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	/* Populate pages — WP-only, so missing faults use normal kernel path */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		(void)*p;  /* read fault: populates with zero page */
	}

	/* Write-protect all pages */
	if (bpf_link_writeprotect(bpf_link__fd(link), (unsigned long)region,
				  region_size, BPF_FAULT_WP_ENABLE) < 0) {
		fprintf(stderr, "BPF_LINK_WRITEPROTECT enable failed: %s\n",
			strerror(errno));
		goto out;
	}

	reset_wp_count(skel);

	/* Write to each page — should trigger WP fault, BPF allows it */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		*p = 'W';
	}

	/* Verify writes landed */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		if (*p != 'W') {
			fprintf(stderr,
				"    FAIL: page %zu: got 0x%02x expected 0x%02x\n",
				i, (unsigned char)*p, 'W');
			goto out;
		}
	}

	/* Verify BPF WP handler was called for each page */
	__u64 count = read_wp_count(skel);

	if (count != num_pages) {
		fprintf(stderr,
			"    FAIL: wp_fault_count = %llu, expected %zu\n",
			(unsigned long long)count, num_pages);
		goto out;
	}

	ret = 0;

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		wp_fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

/*
 * Test 2: WP resolve — after resolving, writes should not fault.
 *
 * WP pages, then resolve WP, then write.  The second batch of writes
 * should not trigger any WP faults (counter stays the same).
 */
static int test_wp_resolve(void)
{
	const size_t num_pages = 16;
	const size_t region_size = num_pages * page_size;
	struct wp_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int ret = -1;

	printf("TEST: wp resolve ... ");
	fflush(stdout);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

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

	/* Populate pages */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		(void)*p;
	}

	/* Write-protect */
	if (bpf_link_writeprotect(bpf_link__fd(link), (unsigned long)region,
				  region_size, BPF_FAULT_WP_ENABLE) < 0) {
		fprintf(stderr, "WP enable failed: %s\n", strerror(errno));
		goto out;
	}

	/* Resolve write-protection */
	if (bpf_link_writeprotect(bpf_link__fd(link), (unsigned long)region,
				  region_size, 0) < 0) {
		fprintf(stderr, "WP resolve failed: %s\n", strerror(errno));
		goto out;
	}

	reset_wp_count(skel);

	/* Write to each page — should NOT trigger WP faults */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		*p = 'R';
	}

	/* Verify no WP faults occurred */
	__u64 count = read_wp_count(skel);

	if (count != 0) {
		fprintf(stderr,
			"    FAIL: wp_fault_count = %llu after resolve, expected 0\n",
			(unsigned long long)count);
		goto out;
	}

	/* Verify writes landed */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		if (*p != 'R') {
			fprintf(stderr,
				"    FAIL: page %zu: got 0x%02x expected 0x%02x\n",
				i, (unsigned char)*p, 'R');
			goto out;
		}
	}

	ret = 0;

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		wp_fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

/*
 * Test 3: WP-only does not intercept missing faults.
 *
 * Register with BPF_FAULT_FLAG_WP only.  The BPF handle_page_fault
 * fills pages with 'A', but since VM_BPF_FAULT is not set, missing
 * faults should go through the normal kernel zero-fill path.
 * Verify: pages contain 0x00, not 'A'.
 */
static int test_wp_no_missing(void)
{
	const size_t num_pages = 16;
	const size_t region_size = num_pages * page_size;
	struct wp_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int ret = -1;

	printf("TEST: wp no missing intercept ... ");
	fflush(stdout);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = wp_fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	/* Attach with WP-only flag */
	link = bpf_map__attach_fault_ops(skel->maps.wp_fault_ops,
					 region, region_size,
					 BPF_FAULT_FLAG_WP);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	/* Read-fault each page — should get zero-filled by kernel, NOT 'A' */
	ret = 0;
	for (size_t i = 0; i < num_pages; i++) {
		if (check_page(region, i, 0x00)) {
			fprintf(stderr, "    (page %zu was filled by BPF, "
				"but WP-only should not intercept missing faults)\n", i);
			ret = -1;
			break;
		}
	}

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		wp_fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

/*
 * Test 4: BPF_LINK_WRITEPROTECT requires BPF_FAULT_FLAG_WP on the link.
 *
 * Create a link without the WP flag (default missing-only registration).
 * Attempt BPF_LINK_WRITEPROTECT — should fail with EINVAL.
 */
static int test_wp_flag_required(void)
{
	const size_t num_pages = 4;
	const size_t region_size = num_pages * page_size;
	struct wp_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int ret = -1;

	printf("TEST: wp flag required ... ");
	fflush(stdout);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = wp_fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	/* Attach WITHOUT WP flag (missing-only) */
	link = bpf_map__attach_fault_ops(skel->maps.wp_fault_ops,
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	/* BPF_LINK_WRITEPROTECT should fail because link has no WP flag */
	if (bpf_link_writeprotect(bpf_link__fd(link), (unsigned long)region,
				  region_size, BPF_FAULT_WP_ENABLE) == 0) {
		fprintf(stderr,
			"    FAIL: writeprotect should have failed without WP flag\n");
		goto out;
	}

	if (errno == EINVAL) {
		ret = 0;
	} else {
		fprintf(stderr, "    FAIL: expected EINVAL, got %s\n",
			strerror(errno));
	}

out:
	if (link)
		bpf_link__destroy(link);
	if (skel)
		wp_fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

/*
 * Test 5: SIGBUS on write-protect faults.
 */
static int test_sigbus_on_wp_fault(void)
{
	const size_t num_pages = 8;
	const size_t region_size = num_pages * page_size;
	struct sigbus_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct sigaction old_sa;
	int handler_installed = 0;
	int ret = -1;

	printf("TEST: sigbus on wp fault ... ");
	fflush(stdout);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = sigbus_fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.sigbus_fault_ops,
					 region, region_size,
					 BPF_FAULT_FLAG_WP);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n", strerror(errno));
		goto out;
	}

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		(void)*p;
	}

	if (bpf_link_writeprotect(bpf_link__fd(link), (unsigned long)region,
				  region_size, BPF_FAULT_WP_ENABLE) < 0) {
		fprintf(stderr, "BPF_LINK_WRITEPROTECT enable failed: %s\n",
			strerror(errno));
		goto out;
	}

	if (install_sigbus_handler(&old_sa) < 0)
		goto out;
	handler_installed = 1;

	skel->bss->wp_fault_count = 0;

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		sigbus_received = 0;
		sigbus_addr = NULL;

		if (sigsetjmp(jmp_env, 1) == 0) {
			*p = 'W';
			fprintf(stderr,
				"    FAIL: page %zu: no SIGBUS received\n", i);
			goto out;
		}

		if (!sigbus_received) {
			fprintf(stderr,
				"    FAIL: page %zu: longjmp but no SIGBUS\n", i);
			goto out;
		}

		{
			unsigned long fault = (unsigned long)sigbus_addr;
			unsigned long page_start = (unsigned long)region + i * page_size;

			if (fault < page_start ||
			    fault >= page_start + (unsigned long)page_size) {
				fprintf(stderr,
					"    FAIL: page %zu: si_addr=%lx expected [%lx,%lx)\n",
					i, fault, page_start,
					page_start + (unsigned long)page_size);
				goto out;
			}
		}
	}

	if (skel->bss->wp_fault_count != num_pages) {
		fprintf(stderr,
			"    FAIL: wp_fault_count = %llu, expected %zu\n",
			(unsigned long long)skel->bss->wp_fault_count, num_pages);
		goto out;
	}

	ret = 0;

out:
	if (handler_installed)
		sigaction(SIGBUS, &old_sa, NULL);
	if (link)
		bpf_link__destroy(link);
	if (skel)
		sigbus_fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

/*
 * Test 6: Resolving WP restores normal write path (no SIGBUS).
 */
static int test_wp_normal_after_resolve(void)
{
	const size_t num_pages = 8;
	const size_t region_size = num_pages * page_size;
	struct sigbus_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct sigaction old_sa;
	int handler_installed = 0;
	int ret = -1;

	printf("TEST: wp normal after resolve ... ");
	fflush(stdout);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}

	skel = sigbus_fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.sigbus_fault_ops,
					 region, region_size,
					 BPF_FAULT_FLAG_WP);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n", strerror(errno));
		goto out;
	}

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		(void)*p;
	}

	if (bpf_link_writeprotect(bpf_link__fd(link), (unsigned long)region,
				  region_size, BPF_FAULT_WP_ENABLE) < 0) {
		fprintf(stderr, "WP enable failed: %s\n", strerror(errno));
		goto out;
	}

	if (bpf_link_writeprotect(bpf_link__fd(link), (unsigned long)region,
				  region_size, 0) < 0) {
		fprintf(stderr, "WP resolve failed: %s\n", strerror(errno));
		goto out;
	}

	if (install_sigbus_handler(&old_sa) < 0)
		goto out;
	handler_installed = 1;

	skel->bss->wp_fault_count = 0;

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		sigbus_received = 0;
		if (sigsetjmp(jmp_env, 1) == 0) {
			*p = 'R';
		} else {
			fprintf(stderr,
				"    FAIL: page %zu: got SIGBUS after resolve\n", i);
			goto out;
		}

		if (sigbus_received) {
			fprintf(stderr,
				"    FAIL: page %zu: SIGBUS flag set after resolve\n", i);
			goto out;
		}

		if (*p != 'R') {
			fprintf(stderr,
				"    FAIL: page %zu: got 0x%02x expected 0x%02x\n",
				i, (unsigned char)*p, 'R');
			goto out;
		}
	}

	if (skel->bss->wp_fault_count != 0) {
		fprintf(stderr,
			"    FAIL: wp_fault_count = %llu after resolve, expected 0\n",
			(unsigned long long)skel->bss->wp_fault_count);
		goto out;
	}

	ret = 0;

out:
	if (handler_installed)
		sigaction(SIGBUS, &old_sa, NULL);
	if (link)
		bpf_link__destroy(link);
	if (skel)
		sigbus_fault_ops_bpf__destroy(skel);
	if (region != MAP_FAILED)
		munmap(region, region_size);

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

int main(void)
{
	int failures = 0;
	int total = 6;

	page_size = sysconf(_SC_PAGESIZE);

	printf("=== bpf_fault write-protect tests ===\n");

	if (test_wp_basic())
		failures++;
	if (test_wp_resolve())
		failures++;
	if (test_wp_no_missing())
		failures++;
	if (test_wp_flag_required())
		failures++;
	if (test_sigbus_on_wp_fault())
		failures++;
	if (test_wp_normal_after_resolve())
		failures++;

	printf("\n%d/%d tests passed\n", total - failures, total);

	return failures ? 1 : 0;
}
