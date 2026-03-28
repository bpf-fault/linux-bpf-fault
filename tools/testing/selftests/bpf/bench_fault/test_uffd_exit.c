// SPDX-License-Identifier: GPL-2.0-only
/*
 * Reproducer: bpf_fault_exit_mm NULL deref with userfaultfd VMAs.
 *
 * bpf_fault_exit_mm() walks every VMA on process exit and reads
 * vm_userfaultfd_ctx.bpf_ctx without checking VM_BPF_FAULT first.
 * Since bpf_ctx and ctx are a union, a userfaultfd VMA's
 * userfaultfd_ctx pointer is misinterpreted as a bpf_fault_ctx,
 * causing a NULL pointer dereference when the code reads
 * bpf_fault_ctx->mm (which maps to an unlocked spinlock = 0 inside
 * the userfaultfd_ctx).
 *
 * To trigger: register userfaultfd SIGBUS on a VMA, then exit.
 * The crash happens in the exiting process's __mmput path.
 * No bpf_fault involvement or fork needed.
 *
 * The crash is alignment-dependent: it only fires when the
 * userfaultfd_ctx slab address makes the low byte at offset 8
 * (fault_pending_wqh.head.next, read as bpf_fault_ctx.released)
 * equal to zero.  We spawn many short-lived children to increase
 * the chance of hitting the right alignment.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>

static long page_size;

/*
 * Child process: register userfaultfd SIGBUS on a VMA, then exit.
 * The exit path triggers __mmput -> bpf_fault_exit_mm which
 * misinterprets the userfaultfd_ctx as bpf_fault_ctx.
 */
static void child_work(void)
{
	struct uffdio_api api = {
		.api = UFFD_API,
		.features = UFFD_FEATURE_SIGBUS,
	};
	struct uffdio_register reg;
	void *region;
	int fd;

	region = mmap(NULL, page_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED)
		_exit(1);

	fd = syscall(__NR_userfaultfd,
		     O_CLOEXEC | O_NONBLOCK | UFFD_USER_MODE_ONLY);
	if (fd < 0)
		_exit(1);

	if (ioctl(fd, UFFDIO_API, &api) < 0)
		_exit(1);

	reg.range.start = (unsigned long)region;
	reg.range.len = page_size;
	reg.mode = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(fd, UFFDIO_REGISTER, &reg) < 0)
		_exit(1);

	/*
	 * Exit with userfaultfd VMA still registered.
	 * __mmput -> bpf_fault_exit_mm will walk this VMA.
	 */
	_exit(0);
}

int main(void)
{
	int i, failed = 0;

	page_size = sysconf(_SC_PAGESIZE);

	printf("TEST: userfaultfd VMA + bpf_fault_exit_mm ... ");
	fflush(stdout);

	/*
	 * Spawn many children.  Each registers userfaultfd and exits.
	 * If the bug is present, one of them will crash in
	 * bpf_fault_exit_mm depending on slab alignment.
	 */
	for (i = 0; i < 200; i++) {
		pid_t pid = fork();

		if (pid < 0) {
			perror("fork");
			return 1;
		}

		if (pid == 0)
			child_work();

		int status;

		if (waitpid(pid, &status, 0) < 0) {
			perror("waitpid");
			return 1;
		}

		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
			failed++;
	}

	if (failed) {
		printf("FAIL (%d children crashed)\n", failed);
		return 1;
	}

	printf("PASS\n");
	return 0;
}
