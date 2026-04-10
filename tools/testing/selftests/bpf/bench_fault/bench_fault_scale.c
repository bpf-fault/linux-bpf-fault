// SPDX-License-Identifier: GPL-2.0-only
/*
 * Scalability benchmark: userfaultfd vs bpf_fault page fault handling.
 *
 * Spawns T worker threads, each touching N pages in a disjoint slice of a
 * shared anonymous mapping.  Measures total wall-clock time for all threads
 * to finish their faults.
 *
 * For userfaultfd, a single handler thread services all faults through one
 * uffd descriptor — this is the typical deployment and exposes the IPC
 * scalability bottleneck.
 *
 * For bpf_fault, faults are handled in-kernel in the faulting thread's
 * context — no IPC, scales with the number of threads.
 *
 * Output: one machine-parseable line per run:
 *   mode=<mode> threads=<T> pages_per_thread=<N> total_faults=<F> wall_ns=<W>
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "fault_ops.skel.h"
#include "bench_fault_util.h"

static int cdf_mode;

/* ------------------------------------------------------------------ */
/*  CPU time tracking via getrusage                                    */
/* ------------------------------------------------------------------ */

static uint64_t tv_to_us(struct timeval *tv)
{
	return (uint64_t)tv->tv_sec * 1000000ULL + tv->tv_usec;
}

static uint64_t cpu_time_us(struct rusage *before, struct rusage *after)
{
	uint64_t user = tv_to_us(&after->ru_utime) - tv_to_us(&before->ru_utime);
	uint64_t sys  = tv_to_us(&after->ru_stime) - tv_to_us(&before->ru_stime);

	return user + sys;
}

/* ------------------------------------------------------------------ */
/*  Worker thread context                                              */
/* ------------------------------------------------------------------ */

struct worker_ctx {
	void		*base;		/* start of this thread's slice */
	size_t		num_pages;
	size_t		page_size;
	pthread_barrier_t *barrier;
	uint64_t	elapsed_ns;	/* per-thread fault time */
};

/* ------------------------------------------------------------------ */
/*  Per-thread CDF output                                              */
/* ------------------------------------------------------------------ */

static void print_per_thread_times(const char *mode, int num_threads,
				   struct worker_ctx *workers)
{
	if (!cdf_mode)
		return;

	for (int i = 0; i < num_threads; i++)
		printf("cdf mode=%s thread=%d elapsed_ns=%lu\n",
		       mode, i, (unsigned long)workers[i].elapsed_ns);
}

static void *worker_thread(void *arg)
{
	struct worker_ctx *w = arg;
	uint64_t t0, t1;

	pthread_barrier_wait(w->barrier);
	t0 = now_ns();

	for (size_t i = 0; i < w->num_pages; i++) {
		volatile char *p = (volatile char *)w->base + i * w->page_size;
		char c = *p;	/* trigger fault */
		(void)c;
	}

	t1 = now_ns();
	w->elapsed_ns = t1 - t0;
	return NULL;
}

static void *baseline_worker_thread(void *arg)
{
	struct worker_ctx *w = arg;
	uint64_t t0, t1;

	pthread_barrier_wait(w->barrier);
	t0 = now_ns();

	for (size_t i = 0; i < w->num_pages; i++) {
		void *p = (char *)w->base + i * w->page_size;

		memset(p, FILL_BYTE, w->page_size);
	}

	t1 = now_ns();
	w->elapsed_ns = t1 - t0;
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  userfaultfd handler thread                                         */
/* ------------------------------------------------------------------ */

struct uffd_handler_ctx {
	int		uffd;
	size_t		page_size;
	volatile int	done;
};

static void *uffd_handler_thread(void *arg)
{
	struct uffd_handler_ctx *h = arg;
	struct uffdio_copy uc;
	char *src_page;

	src_page = mmap(NULL, h->page_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (src_page == MAP_FAILED) {
		perror("mmap src_page");
		return NULL;
	}
	memset(src_page, FILL_BYTE, h->page_size);

	for (;;) {
		struct uffd_msg msg;
		struct pollfd pfd = {
			.fd	= h->uffd,
			.events	= POLLIN,
		};
		ssize_t nread;

		if (poll(&pfd, 1, 100) <= 0) {
			if (h->done)
				break;
			continue;
		}

		nread = read(h->uffd, &msg, sizeof(msg));
		if (nread <= 0) {
			if (h->done)
				break;
			if (nread < 0 && errno == EAGAIN)
				continue;
			break;
		}

		if (msg.event != UFFD_EVENT_PAGEFAULT)
			continue;

		uc.dst  = msg.arg.pagefault.address & ~(h->page_size - 1);
		uc.src  = (unsigned long)src_page;
		uc.len  = h->page_size;
		uc.mode = 0;
		uc.copy = 0;

		if (ioctl(h->uffd, UFFDIO_COPY, &uc) < 0) {
			if (errno != EEXIST)
				perror("UFFDIO_COPY");
		}
	}

	munmap(src_page, h->page_size);
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  Benchmark: baseline (kernel anonymous faults)                      */
/* ------------------------------------------------------------------ */

static int bench_baseline(int num_threads, size_t pages_per_thread)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t total_pages = (size_t)num_threads * pages_per_thread;
	size_t region_size = total_pages * page_size;
	pthread_barrier_t barrier;
	pthread_t *threads;
	struct worker_ctx *workers;
	void *region;
	struct rusage ru_before, ru_after;
	uint64_t t_start, t_end;

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	pthread_barrier_init(&barrier, NULL, num_threads + 1);
	threads = calloc(num_threads, sizeof(pthread_t));
	workers = calloc(num_threads, sizeof(struct worker_ctx));

	for (int i = 0; i < num_threads; i++) {
		workers[i] = (struct worker_ctx){
			.base      = (char *)region + (size_t)i * pages_per_thread * page_size,
			.num_pages = pages_per_thread,
			.page_size = page_size,
			.barrier   = &barrier,
		};
		pthread_create(&threads[i], NULL, baseline_worker_thread, &workers[i]);
	}

	/* Release all workers simultaneously */
	getrusage(RUSAGE_SELF, &ru_before);
	t_start = now_ns();
	pthread_barrier_wait(&barrier);

	for (int i = 0; i < num_threads; i++)
		pthread_join(threads[i], NULL);
	t_end = now_ns();
	getrusage(RUSAGE_SELF, &ru_after);

	printf("mode=baseline threads=%d pages_per_thread=%zu total_faults=%zu wall_ns=%lu cpu_us=%lu\n",
	       num_threads, pages_per_thread, total_pages, t_end - t_start,
	       cpu_time_us(&ru_before, &ru_after));
	print_per_thread_times("baseline", num_threads, workers);

	munmap(region, region_size);
	pthread_barrier_destroy(&barrier);
	free(threads);
	free(workers);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Benchmark: userfaultfd                                             */
/* ------------------------------------------------------------------ */

static int bench_userfaultfd(int num_threads, size_t pages_per_thread)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t total_pages = (size_t)num_threads * pages_per_thread;
	size_t region_size = total_pages * page_size;
	pthread_barrier_t barrier;
	pthread_t *threads;
	struct worker_ctx *workers;
	void *region;
	int uffd;
	struct uffdio_api api;
	struct uffdio_register reg;
	struct uffd_handler_ctx hctx;
	pthread_t handler;
	struct rusage ru_before, ru_after;
	uint64_t t_start, t_end;

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0) {
		perror("userfaultfd");
		munmap(region, region_size);
		return -1;
	}

	api.api = UFFD_API;
	api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &api) < 0) {
		perror("UFFDIO_API");
		close(uffd);
		munmap(region, region_size);
		return -1;
	}

	reg.range.start = (unsigned long)region;
	reg.range.len   = region_size;
	reg.mode        = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) {
		perror("UFFDIO_REGISTER");
		close(uffd);
		munmap(region, region_size);
		return -1;
	}

	hctx = (struct uffd_handler_ctx){
		.uffd      = uffd,
		.page_size = page_size,
		.done      = 0,
	};
	pthread_create(&handler, NULL, uffd_handler_thread, &hctx);

	pthread_barrier_init(&barrier, NULL, num_threads + 1);
	threads = calloc(num_threads, sizeof(pthread_t));
	workers = calloc(num_threads, sizeof(struct worker_ctx));

	for (int i = 0; i < num_threads; i++) {
		workers[i] = (struct worker_ctx){
			.base      = (char *)region + (size_t)i * pages_per_thread * page_size,
			.num_pages = pages_per_thread,
			.page_size = page_size,
			.barrier   = &barrier,
		};
		pthread_create(&threads[i], NULL, worker_thread, &workers[i]);
	}

	getrusage(RUSAGE_SELF, &ru_before);
	t_start = now_ns();
	pthread_barrier_wait(&barrier);

	for (int i = 0; i < num_threads; i++)
		pthread_join(threads[i], NULL);
	t_end = now_ns();
	getrusage(RUSAGE_SELF, &ru_after);

	hctx.done = 1;
	pthread_join(handler, NULL);
	close(uffd);

	printf("mode=uffd threads=%d pages_per_thread=%zu total_faults=%zu wall_ns=%lu cpu_us=%lu\n",
	       num_threads, pages_per_thread, total_pages, t_end - t_start,
	       cpu_time_us(&ru_before, &ru_after));
	print_per_thread_times("uffd", num_threads, workers);

	munmap(region, region_size);
	pthread_barrier_destroy(&barrier);
	free(threads);
	free(workers);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Benchmark: bpf_fault                                               */
/* ------------------------------------------------------------------ */

static int bench_bpf_fault(int num_threads, size_t pages_per_thread)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t total_pages = (size_t)num_threads * pages_per_thread;
	size_t region_size = total_pages * page_size;
	pthread_barrier_t barrier;
	pthread_t *threads;
	struct worker_ctx *workers;
	void *region;
	struct fault_ops_bpf *skel;
	struct bpf_link *link;
	struct rusage ru_before, ru_after;
	uint64_t t_start, t_end;

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	skel = fault_ops_bpf__open();
	if (!skel) {
		fprintf(stderr, "Failed to open BPF skeleton\n");
		munmap(region, region_size);
		return -1;
	}

	if (fault_ops_bpf__load(skel)) {
		fprintf(stderr, "Failed to load BPF program: %s\n",
			strerror(errno));
		fault_ops_bpf__destroy(skel);
		munmap(region, region_size);
		return -1;
	}

	link = bpf_map__attach_fault_ops(skel->maps.bench_fault_ops,
					 region, region_size, 0);
	if (!link) {
		fprintf(stderr, "Failed to attach fault_ops: %s\n",
			strerror(errno));
		fault_ops_bpf__destroy(skel);
		munmap(region, region_size);
		return -1;
	}

	pthread_barrier_init(&barrier, NULL, num_threads + 1);
	threads = calloc(num_threads, sizeof(pthread_t));
	workers = calloc(num_threads, sizeof(struct worker_ctx));

	for (int i = 0; i < num_threads; i++) {
		workers[i] = (struct worker_ctx){
			.base      = (char *)region + (size_t)i * pages_per_thread * page_size,
			.num_pages = pages_per_thread,
			.page_size = page_size,
			.barrier   = &barrier,
		};
		pthread_create(&threads[i], NULL, worker_thread, &workers[i]);
	}

	getrusage(RUSAGE_SELF, &ru_before);
	t_start = now_ns();
	pthread_barrier_wait(&barrier);

	for (int i = 0; i < num_threads; i++)
		pthread_join(threads[i], NULL);
	t_end = now_ns();
	getrusage(RUSAGE_SELF, &ru_after);

	bpf_link__destroy(link);
	fault_ops_bpf__destroy(skel);

	printf("mode=bpf threads=%d pages_per_thread=%zu total_faults=%zu wall_ns=%lu cpu_us=%lu\n",
	       num_threads, pages_per_thread, total_pages, t_end - t_start,
	       cpu_time_us(&ru_before, &ru_after));
	print_per_thread_times("bpf", num_threads, workers);

	munmap(region, region_size);
	pthread_barrier_destroy(&barrier);
	free(threads);
	free(workers);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Benchmark: mprotect + SIGSEGV                                      */
/* ------------------------------------------------------------------ */

static size_t g_page_size;

static void sigsegv_handler(int sig, siginfo_t *si, void *ctx)
{
	unsigned long addr = (unsigned long)si->si_addr;
	unsigned long page = addr & ~(g_page_size - 1);

	if (mprotect((void *)page, g_page_size, PROT_READ | PROT_WRITE) < 0)
		_exit(1);

	memset((void *)page, FILL_BYTE, g_page_size);
}

static int bench_sigsegv(int num_threads, size_t pages_per_thread)
{
	size_t page_size = sysconf(_SC_PAGESIZE);
	size_t total_pages = (size_t)num_threads * pages_per_thread;
	size_t region_size = total_pages * page_size;
	pthread_barrier_t barrier;
	pthread_t *threads;
	struct worker_ctx *workers;
	void *region;
	struct sigaction sa, old_sa;
	struct rusage ru_before, ru_after;
	uint64_t t_start, t_end;

	g_page_size = page_size;

	region = mmap(NULL, region_size, PROT_NONE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		return -1;
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = sigsegv_handler;
	sa.sa_flags = SA_SIGINFO;
	sigemptyset(&sa.sa_mask);
	if (sigaction(SIGSEGV, &sa, &old_sa) < 0) {
		perror("sigaction");
		munmap(region, region_size);
		return -1;
	}

	pthread_barrier_init(&barrier, NULL, num_threads + 1);
	threads = calloc(num_threads, sizeof(pthread_t));
	workers = calloc(num_threads, sizeof(struct worker_ctx));

	for (int i = 0; i < num_threads; i++) {
		workers[i] = (struct worker_ctx){
			.base      = (char *)region + (size_t)i * pages_per_thread * page_size,
			.num_pages = pages_per_thread,
			.page_size = page_size,
			.barrier   = &barrier,
		};
		pthread_create(&threads[i], NULL, worker_thread, &workers[i]);
	}

	getrusage(RUSAGE_SELF, &ru_before);
	t_start = now_ns();
	pthread_barrier_wait(&barrier);

	for (int i = 0; i < num_threads; i++)
		pthread_join(threads[i], NULL);
	t_end = now_ns();
	getrusage(RUSAGE_SELF, &ru_after);

	sigaction(SIGSEGV, &old_sa, NULL);

	printf("mode=sigsegv threads=%d pages_per_thread=%zu total_faults=%zu wall_ns=%lu cpu_us=%lu\n",
	       num_threads, pages_per_thread, total_pages, t_end - t_start,
	       cpu_time_us(&ru_before, &ru_after));
	print_per_thread_times("sigsegv", num_threads, workers);

	munmap(region, region_size);
	pthread_barrier_destroy(&barrier);
	free(threads);
	free(workers);
	return 0;
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-t threads] [-n pages_per_thread] [-b uffd|bpf|sigsegv|baseline|all] [-c]\n"
		"  -t  Number of worker threads (default: 1)\n"
		"  -n  Pages per thread (default: 1024)\n"
		"  -b  Benchmark mode: uffd, bpf, sigsegv, baseline, or all (default: all)\n"
		"  -c  Print per-thread completion times (for CDF plots)\n",
		prog);
}

int main(int argc, char **argv)
{
	int num_threads = 1;
	size_t pages_per_thread = 1024;
	int do_baseline = 1, do_uffd = 1, do_bpf = 1, do_sigsegv = 1;
	int opt;

	while ((opt = getopt(argc, argv, "t:n:b:ch")) != -1) {
		switch (opt) {
		case 't':
			num_threads = atoi(optarg);
			if (num_threads < 1) {
				fprintf(stderr, "threads must be >= 1\n");
				return 1;
			}
			break;
		case 'n':
			pages_per_thread = strtoul(optarg, NULL, 0);
			break;
		case 'c':
			cdf_mode = 1;
			break;
		case 'b':
			do_baseline = 0;
			do_uffd = 0;
			do_bpf = 0;
			do_sigsegv = 0;
			if (strcmp(optarg, "uffd") == 0) {
				do_uffd = 1;
			} else if (strcmp(optarg, "bpf") == 0) {
				do_bpf = 1;
			} else if (strcmp(optarg, "sigsegv") == 0) {
				do_sigsegv = 1;
			} else if (strcmp(optarg, "baseline") == 0) {
				do_baseline = 1;
			} else if (strcmp(optarg, "all") == 0) {
				do_baseline = 1;
				do_uffd = 1;
				do_bpf = 1;
				do_sigsegv = 1;
			} else {
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

	if (do_baseline)
		bench_baseline(num_threads, pages_per_thread);
	if (do_uffd)
		bench_userfaultfd(num_threads, pages_per_thread);
	if (do_sigsegv)
		bench_sigsegv(num_threads, pages_per_thread);
	if (do_bpf)
		bench_bpf_fault(num_threads, pages_per_thread);

	return 0;
}
