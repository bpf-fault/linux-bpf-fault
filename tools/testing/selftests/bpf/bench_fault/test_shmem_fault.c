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
#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fault_ops.skel.h"
#include "sigbus_fault_ops.skel.h"

#define FILL_BYTE 'A'

static long page_size;
static sigjmp_buf jmp_env;
static volatile sig_atomic_t sigbus_received;
static volatile void *sigbus_addr;

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

/*
 * Test 5: bpf_fault on shmem with large folios (THP).
 *
 * When CONFIG_TRANSPARENT_HUGEPAGE is enabled and the shmem page cache
 * contains large folios, filemap_lock_folio() can return a folio whose
 * folio->index is less than vmf->pgoff.  The kernel must compute the
 * correct sub-page offset within the large folio when pre-populating
 * the page for the BPF program.
 *
 * This test writes distinct per-page patterns into a tmpfs file, uses
 * MADV_HUGEPAGE to encourage large folio creation, then faults pages
 * through bpf_fault.  We verify:
 *   1. No crashes or kernel warnings (the main regression this catches)
 *   2. All faulted pages contain the BPF fill byte ('A')
 *   3. A control MAP_PRIVATE read (no bpf_fault) sees correct per-page
 *      data, confirming the page cache contents are right.
 */
static int test_large_folio(void)
{
	/*
	 * Use 512 pages (2MB) — the common PMD-size THP boundary.
	 * Even if the system doesn't create a single 2MB folio, the
	 * kernel may still create intermediate-order folios (64K, etc).
	 */
	const size_t num_pages = 512;
	const size_t region_size = num_pages * page_size;
	char path[256];
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	void *control = MAP_FAILED;
	int fd = -1;
	int ret = -1;

	printf("TEST: large folio (THP) shmem ... ");
	fflush(stdout);

	snprintf(path, sizeof(path), "%s/bpf_fault_test_thp.XXXXXX",
		 find_tmpfs());
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		goto out;
	}

	/*
	 * Write a distinct byte pattern per page so we can verify the
	 * page cache returns the right sub-page data.
	 */
	for (size_t i = 0; i < num_pages; i++) {
		char buf[4096];
		unsigned char pattern = (unsigned char)(i & 0xff);

		memset(buf, pattern, sizeof(buf));
		if (write(fd, buf, page_size) != page_size) {
			perror("write");
			goto out;
		}
	}

	/*
	 * Populate the page cache with large folios by mapping shared,
	 * advising MADV_HUGEPAGE, faulting in all pages, then unmapping.
	 * This is best-effort — THP may not be available or the kernel
	 * may choose smaller folios.  The test is still valid either way.
	 */
	{
		void *shared;

		shared = mmap(NULL, region_size, PROT_READ,
			      MAP_SHARED | MAP_POPULATE, fd, 0);
		if (shared != MAP_FAILED) {
			madvise(shared, region_size, MADV_HUGEPAGE);
			/* Touch each page to ensure population */
			for (size_t i = 0; i < num_pages; i++) {
				volatile char *p = (volatile char *)shared +
						   i * page_size;
				(void)*p;
			}
			munmap(shared, region_size);
		}
	}

	/*
	 * Control check: MAP_PRIVATE without bpf_fault should see the
	 * original per-page patterns from the page cache.  This proves
	 * the page cache data is correct before we test bpf_fault.
	 */
	control = mmap(NULL, region_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (control == MAP_FAILED) {
		perror("mmap control");
		goto out;
	}

	for (size_t i = 0; i < num_pages; i++) {
		const unsigned char *p = (const unsigned char *)control +
					 i * page_size;
		unsigned char expected = (unsigned char)(i & 0xff);

		if (p[0] != expected) {
			fprintf(stderr,
				"    FAIL: control page %zu: got 0x%02x expected 0x%02x\n",
				i, p[0], expected);
			munmap(control, region_size);
			goto out;
		}
	}
	munmap(control, region_size);
	control = MAP_FAILED;

	/*
	 * Now test bpf_fault with the same file.  Large folios should
	 * still be in the page cache from the shared mapping above.
	 */
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

	/*
	 * Fault pages in a non-sequential order to increase the chance
	 * of hitting non-zero offsets within large folios.  We fault
	 * odd pages first, then even pages.
	 */
	for (size_t i = 1; i < num_pages; i += 2) {
		volatile char *p = (volatile char *)region + i * page_size;
		(void)*p;
	}
	for (size_t i = 0; i < num_pages; i += 2) {
		volatile char *p = (volatile char *)region + i * page_size;
		(void)*p;
	}

	/* All pages should contain FILL_BYTE from the BPF program */
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
	if (control != MAP_FAILED)
		munmap(control, region_size);
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
 * Test 6: SIGBUS on shmem missing faults.
 *
 * Attach SIGBUS fault_ops on MAP_PRIVATE tmpfs mapping.  Each read fault
 * should be rejected by BPF and delivered as SIGBUS.
 */
static int test_sigbus_on_shmem_missing(void)
{
	const size_t num_pages = 4;
	const size_t region_size = num_pages * page_size;
	char path[256];
	struct sigbus_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct sigaction old_sa;
	int handler_installed = 0;
	int fd = -1;
	int ret = -1;

	printf("TEST: sigbus on shmem missing fault ... ");
	fflush(stdout);

	snprintf(path, sizeof(path), "%s/bpf_fault_test_sigbus_shmem.XXXXXX",
		 find_tmpfs());
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		goto out;
	}

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

	skel = sigbus_fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.sigbus_fault_ops,
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n", strerror(errno));
		goto out;
	}

	if (install_sigbus_handler(&old_sa) < 0)
		goto out;
	handler_installed = 1;

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		sigbus_received = 0;
		sigbus_addr = NULL;

		if (sigsetjmp(jmp_env, 1) == 0) {
			(void)*p;
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

	if (skel->bss->fault_count != num_pages) {
		fprintf(stderr,
			"    FAIL: fault_count = %llu, expected %zu\n",
			(unsigned long long)skel->bss->fault_count, num_pages);
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
	if (fd >= 0) {
		close(fd);
		unlink(path);
	}

	printf("%s\n", ret ? "FAIL" : "OK");
	return ret;
}

/*
 * Test 7: Detach restores normal MAP_PRIVATE shmem faults.
 */
static int test_shmem_normal_after_detach(void)
{
	const size_t num_pages = 4;
	const size_t region_size = num_pages * page_size;
	char path[256];
	struct sigbus_fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct sigaction old_sa;
	int handler_installed = 0;
	int fd = -1;
	int ret = -1;

	printf("TEST: shmem normal after detach ... ");
	fflush(stdout);

	snprintf(path, sizeof(path), "%s/bpf_fault_test_sigbus_shmem_detach.XXXXXX",
		 find_tmpfs());
	fd = mkstemp(path);
	if (fd < 0) {
		perror("mkstemp");
		goto out;
	}

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

	skel = sigbus_fault_ops_bpf__open_and_load();
	if (!skel) {
		fprintf(stderr, "Failed to load BPF skeleton\n");
		goto out;
	}

	link = bpf_map__attach_fault_ops(skel->maps.sigbus_fault_ops,
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n", strerror(errno));
		goto out;
	}

	bpf_link__destroy(link);
	link = NULL;

	if (install_sigbus_handler(&old_sa) < 0)
		goto out;
	handler_installed = 1;

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		sigbus_received = 0;
		if (sigsetjmp(jmp_env, 1) == 0) {
			if (*p != 'X') {
				fprintf(stderr,
					"    FAIL: page %zu: got 0x%02x expected 0x%02x\n",
					i, (unsigned char)*p, 'X');
				goto out;
			}
		} else {
			fprintf(stderr,
				"    FAIL: page %zu: got SIGBUS after detach\n", i);
			goto out;
		}

		if (sigbus_received) {
			fprintf(stderr,
				"    FAIL: page %zu: SIGBUS flag set after detach\n", i);
			goto out;
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
	int total = 7;

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
	if (test_large_folio())
		failures++;
	if (test_sigbus_on_shmem_missing())
		failures++;
	if (test_shmem_normal_after_detach())
		failures++;

	printf("\n%d/%d tests passed\n", total - failures, total);

	return failures ? 1 : 0;
}
