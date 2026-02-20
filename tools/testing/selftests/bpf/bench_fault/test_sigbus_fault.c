// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test: bpf_fault SIGBUS delivery on missing faults.
 *
 * Verifies that a BPF handle_page_fault returning non-zero causes
 * SIGBUS to be delivered to the faulting process:
 *
 *   1. SIGBUS is delivered when BPF rejects a missing fault
 *   2. The faulting address in siginfo matches the touched page
 *   3. BPF handler invocation count is correct
 *   4. After detach, normal zero-fill faults resume (no SIGBUS)
 *
 * Uses sigbus_fault_ops.bpf.c which provides:
 *   - handle_page_fault: returns -1 (reject → SIGBUS), counts invocations
 */
#define _GNU_SOURCE
#include <errno.h>
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "sigbus_fault_ops.skel.h"
#include "sigbus_util.h"

static long page_size;

/*
 * Test 1: SIGBUS on missing fault.
 *
 * Register BPF fault handler that returns -1 for missing faults.
 * Touch a page and verify SIGBUS is delivered with the correct
 * faulting address and that the BPF handler was invoked.
 */
static int test_sigbus_on_missing(void)
{
	const size_t num_pages = 4;
	const size_t region_size = num_pages * page_size;
	struct sigbus_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct sigaction old_sa;
	int handler_installed = 0;
	int ret = -1;

	printf("TEST: sigbus on missing fault ... ");
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
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	if (install_sigbus_handler(&old_sa) < 0)
		goto out;
	handler_installed = 1;

	/* Touch each page — BPF returns -1, expect SIGBUS */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		sigbus_received = 0;
		sigbus_addr = NULL;

		if (sigsetjmp(jmp_env, 1) == 0) {
			/* First return: attempt the faulting access */
			(void)*p;

			/* If we get here, no signal was delivered */
			fprintf(stderr,
				"    FAIL: page %zu: no SIGBUS received\n", i);
			goto out;
		}

		/* Returned from signal handler via siglongjmp */
		if (!sigbus_received) {
			fprintf(stderr,
				"    FAIL: page %zu: longjmp but no SIGBUS\n",
				i);
			goto out;
		}

		/* Verify faulting address is within the expected page */
		unsigned long fault = (unsigned long)sigbus_addr;
		unsigned long page_start = (unsigned long)region +
					   i * page_size;

		if (fault < page_start ||
		    fault >= page_start + (unsigned long)page_size) {
			fprintf(stderr,
				"    FAIL: page %zu: si_addr=%lx expected [%lx,%lx)\n",
				i, fault, page_start,
				page_start + (unsigned long)page_size);
			goto out;
		}
	}

	/* Verify BPF handler was called for each page */
	__u64 count = skel->bss->fault_count;

	if (count != num_pages) {
		fprintf(stderr,
			"    FAIL: fault_count = %llu, expected %zu\n",
			(unsigned long long)count, num_pages);
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
 * Test 2: Normal faults after detach.
 *
 * Attach BPF SIGBUS handler, detach it, then touch pages.
 * After detach, missing faults should use the normal kernel
 * zero-fill path — no SIGBUS, pages contain 0x00.
 */
static int test_normal_after_detach(void)
{
	const size_t num_pages = 4;
	const size_t region_size = num_pages * page_size;
	struct sigbus_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct sigaction old_sa;
	int handler_installed = 0;
	int ret = -1;

	printf("TEST: normal faults after detach ... ");
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
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	/* Detach — destroy the link before touching any pages */
	bpf_link__destroy(link);
	link = NULL;

	if (install_sigbus_handler(&old_sa) < 0)
		goto out;
	handler_installed = 1;

	/* Touch pages — should get normal zero-fill, no SIGBUS */
	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		sigbus_received = 0;

		if (sigsetjmp(jmp_env, 1) == 0) {
			(void)*p;
		} else {
			fprintf(stderr,
				"    FAIL: page %zu: got SIGBUS after detach\n",
				i);
			goto out;
		}

		if (sigbus_received) {
			fprintf(stderr,
				"    FAIL: page %zu: SIGBUS flag set after detach\n",
				i);
			goto out;
		}
	}

	/* Verify pages are zero-filled (normal kernel path) */
	const unsigned char *base = region;

	for (size_t i = 0; i < num_pages; i++) {
		for (long j = 0; j < page_size; j++) {
			if (base[i * page_size + j] != 0) {
				fprintf(stderr,
					"    FAIL: page %zu offset %ld: got 0x%02x expected 0x00\n",
					i, j, base[i * page_size + j]);
				goto out;
			}
		}
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
	int total = 2;

	page_size = sysconf(_SC_PAGESIZE);

	printf("=== bpf_fault SIGBUS tests ===\n");

	if (test_sigbus_on_missing())
		failures++;
	if (test_normal_after_detach())
		failures++;

	printf("\n%d/%d tests passed\n", total - failures, total);

	return failures ? 1 : 0;
}
