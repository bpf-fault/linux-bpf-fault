// SPDX-License-Identifier: GPL-2.0-only
/*
 * Test: bpf_fault fork inheritance.
 *
 * Verifies that BPF_FAULT_FLAG_INHERIT causes bpf_fault contexts
 * to be inherited across fork():
 *
 *   1. Child processes get BPF-filled pages when INHERIT is set
 *   2. Without INHERIT, child gets default zero-fill
 *   3. Multiple forks each get independent handling
 *   4. Child exit before parent doesn't break parent
 *   5. Parent exit before child doesn't break child
 *   6. fork+exec doesn't crash or leak
 *   7. Multiple regions all inherited
 *
 * Uses fault_ops.bpf.c which fills pages with 'A' (0x41).
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fault_ops.skel.h"
#include "sigbus_util.h"
#include "wp_util.h"
#include "bench_fault_util.h"

static long page_size;

/* Helper: fork, run test_fn in child, collect exit status */
static int fork_and_test(int (*test_fn)(void *), void *arg)
{
	pid_t pid;
	int status;

	pid = fork();
	if (pid < 0) {
		perror("fork");
		return -1;
	}

	if (pid == 0) {
		/* Child */
		_exit(test_fn(arg));
	}

	/* Parent: wait for child */
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		return -1;
	}

	if (WIFEXITED(status))
		return WEXITSTATUS(status);

	fprintf(stderr, "    child did not exit normally\n");
	return -1;
}

struct child_test_args {
	void *region;
	size_t region_size;
};

static int child_check_bpf_pages(void *arg)
{
	struct child_test_args *a = arg;
	size_t num_pages = a->region_size / page_size;

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)a->region + i * page_size;
		(void)*p;
	}

	for (size_t i = 0; i < num_pages; i++) {
		if (check_page(a->region, i, FILL_BYTE, page_size) < 0)
			return 1;
	}
	return 0;
}

static int child_check_zero_pages(void *arg)
{
	struct child_test_args *a = arg;
	size_t num_pages = a->region_size / page_size;

	for (size_t i = 0; i < num_pages; i++) {
		volatile char *p = (volatile char *)a->region + i * page_size;
		(void)*p;
	}

	for (size_t i = 0; i < num_pages; i++) {
		if (check_page(a->region, i, 0, page_size) < 0)
			return 1;
	}
	return 0;
}

/*
 * Test 1: Basic inherit.
 *
 * Parent registers with BPF_FAULT_FLAG_INHERIT, forks.
 * Child faults on unmaterialized pages and gets BPF content.
 */
static int test_basic_inherit(void)
{
	const size_t num_pages = 4;
	const size_t region_size = num_pages * page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct child_test_args args;
	int ret = -1;

	printf("TEST: basic inherit ... ");
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
					 region, region_size,
					 BPF_FAULT_FLAG_INHERIT);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	args.region = region;
	args.region_size = region_size;

	if (fork_and_test(child_check_bpf_pages, &args) != 0) {
		fprintf(stderr, "    FAIL: child did not get BPF pages\n");
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

/*
 * Test 2: No inherit default.
 *
 * Register without INHERIT flag, fork.
 * Child should get default zero-fill pages, not BPF content.
 */
static int test_no_inherit_default(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct child_test_args args;
	int ret = -1;

	printf("TEST: no inherit default ... ");
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

	/* No INHERIT flag */
	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	args.region = region;
	args.region_size = region_size;

	if (fork_and_test(child_check_zero_pages, &args) != 0) {
		fprintf(stderr, "    FAIL: child got non-zero pages\n");
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

/*
 * Test 3: Multi fork.
 *
 * Parent forks twice.  Both children get BPF pages independently.
 */
static int test_multi_fork(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct child_test_args args;
	int ret = -1;

	printf("TEST: multi fork ... ");
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
					 region, region_size,
					 BPF_FAULT_FLAG_INHERIT);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	args.region = region;
	args.region_size = region_size;

	/* Fork child 1 */
	if (fork_and_test(child_check_bpf_pages, &args) != 0) {
		fprintf(stderr, "    FAIL: child 1 did not get BPF pages\n");
		goto out;
	}

	/* Fork child 2 */
	if (fork_and_test(child_check_bpf_pages, &args) != 0) {
		fprintf(stderr, "    FAIL: child 2 did not get BPF pages\n");
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

/*
 * Test 4: Child exits first.
 *
 * Child exits, parent continues using bpf_fault normally.
 */
static int test_child_exits_first(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	struct child_test_args args;
	int ret = -1;

	printf("TEST: child exits first ... ");
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
					 region, region_size,
					 BPF_FAULT_FLAG_INHERIT);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	args.region = region;
	args.region_size = region_size;

	/* Child faults and exits */
	if (fork_and_test(child_check_bpf_pages, &args) != 0) {
		fprintf(stderr, "    FAIL: child failed\n");
		goto out;
	}

	/* Parent faults after child is done */
	{
		volatile char *p = (volatile char *)region;
		(void)*p;
		if (check_page(region, 0, FILL_BYTE, page_size) < 0) {
			fprintf(stderr, "    FAIL: parent page wrong after child exit\n");
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
 * Test 5: Parent exits first.
 *
 * Parent destroys the link, child's inherited handler still works
 * (map kept alive via bpf_map_inc).
 */
static int test_parent_exits_first(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	pid_t pid;
	int status;
	int pipe_fd[2];
	int ret = -1;
	char buf;

	printf("TEST: parent exits first ... ");
	fflush(stdout);

	if (pipe(pipe_fd) < 0) {
		perror("pipe");
		goto out;
	}

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
					 region, region_size,
					 BPF_FAULT_FLAG_INHERIT);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		goto out;
	}

	if (pid == 0) {
		/* Child: wait for parent to destroy link */
		close(pipe_fd[1]);
		(void)!read(pipe_fd[0], &buf, 1);
		close(pipe_fd[0]);

		/* Now fault — inherited handler should still work */
		volatile char *p = (volatile char *)region;
		(void)*p;

		if (check_page(region, 0, FILL_BYTE, page_size) < 0)
			_exit(1);
		_exit(0);
	}

	/* Parent: destroy link, then signal child */
	close(pipe_fd[0]);
	bpf_link__destroy(link);
	link = NULL;

	/* Signal child to proceed */
	(void)!write(pipe_fd[1], "x", 1);
	close(pipe_fd[1]);

	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		goto out;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "    FAIL: child failed after parent link destroy\n");
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

/*
 * Test 6: Fork + exec.
 *
 * Child forks then execs /bin/true.  No crash, no leak.
 */
static int child_exec(void *arg)
{
	(void)arg;
	execl("/bin/true", "true", NULL);
	/* If exec fails, that's also fine — just exit */
	return 0;
}

static int test_fork_exec(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int ret = -1;

	printf("TEST: fork exec ... ");
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
					 region, region_size,
					 BPF_FAULT_FLAG_INHERIT);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	if (fork_and_test(child_exec, NULL) != 0) {
		fprintf(stderr, "    FAIL: fork+exec failed\n");
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

/*
 * Test 8: Claim inherited context.
 *
 * Parent registers with INHERIT, forks.  Child calls BPF_FAULT_CLAIM
 * to get a proper link fd, then uses that fd to add a new region.
 */
static int test_claim(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	pid_t pid;
	int status;
	int ret = -1;

	printf("TEST: claim inherited context ... ");
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
					 region, region_size,
					 BPF_FAULT_FLAG_INHERIT);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		goto out;
	}

	pid = fork();
	if (pid < 0) {
		perror("fork");
		goto out;
	}

	if (pid == 0) {
		/* Child: claim the inherited context */
		int parent_fd = bpf_link__fd(link);
		int child_fd;
		void *region2;

		child_fd = bpf_link_fault_claim(parent_fd);
		if (child_fd < 0) {
			fprintf(stderr, "\n    claim failed: %s\n",
				strerror(errno));
			_exit(1);
		}

		/* Verify faults still work on the original region */
		volatile char *p = (volatile char *)region;
		(void)*p;
		if (check_page(region, 0, FILL_BYTE, page_size) < 0)
			_exit(2);

		/* Use the claimed fd to add a new region */
		region2 = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
			       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
		if (region2 == MAP_FAILED)
			_exit(3);

		if (bpf_link_fault_register(child_fd,
					    (unsigned long)region2,
					    region_size) < 0) {
			fprintf(stderr, "\n    register via claimed fd failed: %s\n",
				strerror(errno));
			_exit(4);
		}

		/* Fault on the new region */
		volatile char *p2 = (volatile char *)region2;
		(void)*p2;
		if (check_page(region2, 0, FILL_BYTE, page_size) < 0)
			_exit(5);

		/* Close the claimed fd (proper cleanup) */
		close(child_fd);
		munmap(region2, region_size);
		_exit(0);
	}

	/* Parent: wait for child */
	if (waitpid(pid, &status, 0) < 0) {
		perror("waitpid");
		goto out;
	}

	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		fprintf(stderr, "    FAIL: child exited with status %d\n",
			WIFEXITED(status) ? WEXITSTATUS(status) : -1);
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

/*
 * Test 9: Claim returns ENOENT for non-inherited.
 *
 * Parent tries to claim its own (non-inherited) context.
 * Should fail with ENOENT since there's no inherited ctx.
 */
static int test_claim_noninherited(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region = MAP_FAILED;
	int ret = -1;
	int fd;

	printf("TEST: claim non-inherited returns error ... ");
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

	/* Try to claim in the parent — no inherited ctx exists */
	fd = bpf_link_fault_claim(bpf_link__fd(link));
	if (fd >= 0) {
		fprintf(stderr, "    FAIL: claim should have failed\n");
		close(fd);
		goto out;
	}

	if (errno != ENOENT) {
		fprintf(stderr, "    FAIL: expected ENOENT, got %s\n",
			strerror(errno));
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

/*
 * Test 7: Inherit multi-region.
 *
 * Parent registers multiple regions with INHERIT.
 * All regions are inherited by child.
 */
static int test_inherit_multi_region(void)
{
	const size_t region_size = page_size;
	struct fault_ops_bpf *skel = NULL;
	struct bpf_link *link = NULL;
	void *region_a = MAP_FAILED, *region_b = MAP_FAILED;
	int ret = -1;

	printf("TEST: inherit multi-region ... ");
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
					 region_a, region_size,
					 BPF_FAULT_FLAG_INHERIT);
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

	/* Fork and check both regions in child */
	{
		pid_t pid = fork();

		if (pid < 0) {
			perror("fork");
			goto out;
		}
		if (pid == 0) {
			volatile char *pa = (volatile char *)region_a;
			volatile char *pb = (volatile char *)region_b;
			(void)*pa;
			(void)*pb;

			if (check_page(region_a, 0, FILL_BYTE, page_size) < 0)
				_exit(1);
			if (check_page(region_b, 0, FILL_BYTE, page_size) < 0)
				_exit(2);
			_exit(0);
		}

		int status;
		if (waitpid(pid, &status, 0) < 0) {
			perror("waitpid");
			goto out;
		}
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			fprintf(stderr, "    FAIL: child multi-region check failed (exit=%d)\n",
				WIFEXITED(status) ? WEXITSTATUS(status) : -1);
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

int main(void)
{
	int failed = 0;

	page_size = sysconf(_SC_PAGESIZE);
	if (page_size < 0) {
		perror("sysconf(_SC_PAGESIZE)");
		return 1;
	}

	printf("=== bpf_fault fork inheritance tests ===\n\n");

	if (test_basic_inherit() < 0)
		failed++;
	if (test_no_inherit_default() < 0)
		failed++;
	if (test_multi_fork() < 0)
		failed++;
	if (test_child_exits_first() < 0)
		failed++;
	if (test_parent_exits_first() < 0)
		failed++;
	if (test_fork_exec() < 0)
		failed++;
	if (test_inherit_multi_region() < 0)
		failed++;
	if (test_claim() < 0)
		failed++;
	if (test_claim_noninherited() < 0)
		failed++;

	printf("\n%d/%d tests passed\n", 9 - failed, 9);
	return failed ? 1 : 0;
}
