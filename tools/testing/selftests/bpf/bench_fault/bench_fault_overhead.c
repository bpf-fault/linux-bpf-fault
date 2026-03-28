// SPDX-License-Identifier: GPL-2.0-only
/*
 * bench_fault_overhead — userfaultfd fault-handling overhead breakdown.
 *
 * Dissects the per-fault latency of a userfaultfd MISSING fault into
 * 17 sub-phases using BPF kprobes, sched_switch/sched_waking
 * tracepoints, and cross-thread userspace timestamps.
 *
 * Timeline for a single page fault (all timestamps marked):
 *
 *   Faulting thread (CPU A)            Handler thread (CPU B)
 *   ──────────────────────             ──────────────────────
 *   t0: touch page -> FAULT            (blocked in poll)
 *       kernel: handle_mm_fault
 *         -> do_anonymous_page
 *   K0:   -> handle_userfault          (BPF kprobe)
 *            enqueue uffd_msg,
 *            wake_up_poll(fd_wqh),
 *   SO:   schedule() [sched_switch]    (BPF tp_btf/sched_switch)
 *                                  SI: sched_switch in
 *                                      t1: poll() returns (POLLIN)
 *                                  RE:   userfaultfd_read_iter (kprobe)
 *                                          ctx_read, refile, copy_to_iter
 *                                  RR:   userfaultfd_read_iter ret (kretprobe)
 *                                      t2: read() returns (uffd_msg)
 *                                      t3: ioctl(UFFDIO_COPY) enters
 *                                  MF:   mfill_atomic_pte_copy (BPF kprobe)
 *                                          alloc page, copy, PTE install
 *                                  KW:   __wake_userfault (BPF kprobe)
 *                                      t4: ioctl() returns
 *   SI:   sched_switch in
 *   K1:   handle_userfault returns     (BPF kretprobe)
 *   t5: back to userspace
 *
 * With -k (17 sub-phases):
 *   1a   Kernel fault path     (K0-t0)       fault entry -> handle_userfault
 *   1b.1 HUF enqueue + state   (WKh-K0)      enqueue msg, set TASK_KILLABLE
 *   1b.2 wake_up_poll -> sched  (SO-WKh)      wake handler, call schedule()
 *   1b.3 Ctx switch ->handler  (SI-SO)        exact context switch time
 *   1b.4 Handler poll return   (t1-SI)        poll() returns to userspace
 *   2a   read() syscall entry  (RE-t1)        sys_read -> vfs_read dispatch
 *   2b   uffd msg delivery     (RR-RE)        userfaultfd_read_iter work
 *   2c   read() syscall exit   (t2-RR)        VFS return + syscall exit
 *   3    User processing       (t3-t2)        handler argument preparation
 *   4a1  ioctl overhead        (MF-t3)        syscall entry, VMA lock
 *   4a2  Page alloc + copy     (IP-MF)        vma_alloc_folio, copy_from_user
 *   4a3  PTE install + rmap    (KW-IP)        pte lock, set_pte_at, TLB
 *   4b   Wake + ioctl return   (t4-KW)        overlaps with 5a (parallel)
 *   5a1  Wake processing       (WKf-KW)       __wake_userfault spinlock+wake
 *   5a2  IPI + schedule        (SI-WKf)       IPI delivery + scheduler
 *   5a3  HUF cleanup           (K1-SI)        handle_userfault unwind
 *   5b   Kernel->user          (t5-K1)        fault unwind to userspace
 *
 *   Note: 4b overlaps with 5a1-5b (handler and faulter run in
 *   parallel after the wake).  All phases except 4b sum to total.
 *
 * Also measures:
 *   - Context switch latency (pipe ping-pong between the two CPUs)
 *   - Baseline page fault cost (no uffd, kernel zero-fill)
 *
 * Usage:
 *   ./bench_fault_overhead [-n pages] [-w warmup] [-r rounds]
 *                          [-c fault_cpu,handler_cpu] [-k] [-C]
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "overhead_kprobe.skel.h"
#include "bench_fault_util.h"

#define NPHASES		17
#define POLL_TIMEOUT_MS	500
#define NUM_PROBE_HITS	12	/* BPF probe firings per fault */
#define CALIB_PAGES	1024	/* pages for probe overhead calibration */

/* Matches struct kernel_fault_ts in overhead_kprobe.bpf.c */
struct kernel_fault_ts {
	uint64_t t_huf_entry;
	uint64_t t_huf_return;
	uint64_t t_wake;
	uint64_t t_sched_out_faulter;
	uint64_t t_sched_in_handler;
	uint64_t t_sched_in_faulter;
	uint64_t t_mfill_entry;
	uint64_t t_sched_waking_handler;
	uint64_t t_sched_waking_faulter;
	uint64_t t_mfill_install_pte;
	uint64_t t_read_entry;
	uint64_t t_read_return;
};

struct fault_ts {
	uint64_t t_fault_start;		/* t0 */
	uint64_t t_fault_done;		/* t5 */
	uint64_t t_poll_done;		/* t1 */
	uint64_t t_read_done;		/* t2 */
	uint64_t t_ioctl_start;	/* t3 */
	uint64_t t_ioctl_done;		/* t4 */
	uint64_t t_huf_entry;		/* K0 */
	uint64_t t_huf_return;		/* K1 */
	uint64_t t_wake;		/* KW */
	uint64_t t_sched_out_faulter;	/* SO */
	uint64_t t_sched_in_handler;	/* SI (handler) */
	uint64_t t_sched_in_faulter;	/* SI (faulter) */
	uint64_t t_mfill_entry;		/* MF */
	uint64_t t_sched_waking_handler;/* WKh */
	uint64_t t_sched_waking_faulter;/* WKf */
	uint64_t t_mfill_install_pte;	/* IP */
	uint64_t t_read_entry;		/* RE (userfaultfd_read_iter entry) */
	uint64_t t_read_return;		/* RR (userfaultfd_read_iter return) */
} __attribute__((aligned(128)));

struct handler_args {
	int		uffd;
	size_t		page_size;
	size_t		num_pages;
	void		*region;
	struct fault_ts	*ts;
	int		cpu;
	volatile int	done;
	volatile uint32_t handler_tid;
};

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static inline int64_t clamp_pos(int64_t v) { return v > 0 ? v : 0; }

/* Compute (a - b) clamped to >= 0, but return 0 if either endpoint is missing */
static inline int64_t phase_delta(uint64_t a, uint64_t b)
{
	if (!a || !b)
		return 0;
	return clamp_pos((int64_t)(a - b));
}

static void pin_to_cpu(int cpu)
{
	cpu_set_t set;

	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	if (sched_setaffinity(0, sizeof(set), &set))
		fprintf(stderr, "  warning: pin to CPU %d failed: %s\n",
			cpu, strerror(errno));
}

static uint64_t calibrate_timer(void)
{
	const int N = 100000;
	uint64_t start, end;

	start = now_ns();
	for (int i = 0; i < N; i++)
		now_ns();
	end = now_ns();

	return (end - start) / N;
}

static int cmp_i64(const void *a, const void *b)
{
	int64_t va = *(const int64_t *)a;
	int64_t vb = *(const int64_t *)b;

	return (va > vb) - (va < vb);
}

struct phase_stat {
	int64_t avg;
	int64_t min;
	int64_t max;
	int64_t p50;
	int64_t p99;
	double pct;
};

static struct phase_stat compute_stat(int64_t *lat, size_t n,
				      int64_t total_avg)
{
	struct phase_stat s = { 0 };
	int64_t sum = 0;

	if (!n)
		return s;

	qsort(lat, n, sizeof(int64_t), cmp_i64);

	s.min = lat[0];
	s.max = lat[n - 1];
	for (size_t i = 0; i < n; i++)
		sum += lat[i];
	s.avg = sum / (int64_t)n;
	s.p50 = lat[n / 2];
	s.p99 = lat[(size_t)(n * 0.99)];
	s.pct = total_avg > 0 ? 100.0 * s.avg / total_avg : 0;

	return s;
}

/* ------------------------------------------------------------------ */
/*  Context switch latency calibration (pipe ping-pong)                */
/* ------------------------------------------------------------------ */

struct pingpong_args {
	int read_fd;
	int write_fd;
	int cpu;
	int iterations;
};

static void *pingpong_thread(void *arg)
{
	struct pingpong_args *pp = arg;
	char buf;

	pin_to_cpu(pp->cpu);

	for (int i = 0; i < pp->iterations; i++) {
		if (read(pp->read_fd, &buf, 1) != 1)
			break;
		if (write(pp->write_fd, &buf, 1) != 1)
			break;
	}
	return NULL;
}

static int64_t measure_ctx_switch(int cpu_a, int cpu_b)
{
	int pipe_ab[2], pipe_ba[2];
	pthread_t pong;
	struct pingpong_args pp;
	const int iterations = 10000;
	uint64_t start, end;
	char buf = 'x';

	if (pipe(pipe_ab) || pipe(pipe_ba)) {
		perror("pipe");
		return 0;
	}

	const int warmup_iters = 100;

	pp = (struct pingpong_args){
		.read_fd    = pipe_ab[0],
		.write_fd   = pipe_ba[1],
		.cpu        = cpu_b,
		.iterations = warmup_iters + iterations,
	};
	pthread_create(&pong, NULL, pingpong_thread, &pp);

	pin_to_cpu(cpu_a);

	for (int i = 0; i < warmup_iters; i++) {
		(void)!write(pipe_ab[1], &buf, 1);
		(void)!read(pipe_ba[0], &buf, 1);
	}

	start = now_ns();
	for (int i = 0; i < iterations; i++) {
		(void)!write(pipe_ab[1], &buf, 1);
		(void)!read(pipe_ba[0], &buf, 1);
	}
	end = now_ns();

	pthread_join(pong, NULL);
	close(pipe_ab[0]); close(pipe_ab[1]);
	close(pipe_ba[0]); close(pipe_ba[1]);

	return (int64_t)(end - start) / (2 * iterations);
}

/* ------------------------------------------------------------------ */
/*  UFFD handler thread                                                */
/* ------------------------------------------------------------------ */

static void *uffd_handler_thread(void *arg)
{
	struct handler_args *ha = arg;
	struct uffdio_copy uc;
	char *src_page;
	ssize_t nread;

	pin_to_cpu(ha->cpu);
	ha->handler_tid = (uint32_t)syscall(SYS_gettid);

	src_page = mmap(NULL, ha->page_size, PROT_READ | PROT_WRITE,
			MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (src_page == MAP_FAILED) {
		perror("mmap src_page");
		return NULL;
	}
	memset(src_page, FILL_BYTE, ha->page_size);

	for (;;) {
		struct uffd_msg msg;
		struct pollfd pfd = {
			.fd     = ha->uffd,
			.events = POLLIN,
		};
		uint64_t t_poll, t_read, t_ioctl_s, t_ioctl_d;
		unsigned long addr;
		size_t idx;
		int ret;

		ret = poll(&pfd, 1, POLL_TIMEOUT_MS);
		if (ret <= 0) {
			if (ha->done)
				break;
			continue;
		}
		t_poll = now_ns();

		nread = read(ha->uffd, &msg, sizeof(msg));
		t_read = now_ns();

		if (nread <= 0) {
			if (ha->done)
				break;
			continue;
		}
		if (msg.event != UFFD_EVENT_PAGEFAULT)
			continue;

		addr = msg.arg.pagefault.address & ~(ha->page_size - 1);
		idx = (addr - (unsigned long)ha->region) / ha->page_size;

		uc.dst  = addr;
		uc.src  = (unsigned long)src_page;
		uc.len  = ha->page_size;
		uc.mode = 0;
		uc.copy = 0;

		t_ioctl_s = now_ns();

		if (ioctl(ha->uffd, UFFDIO_COPY, &uc) < 0) {
			if (errno != EEXIST)
				perror("UFFDIO_COPY");
		}

		t_ioctl_d = now_ns();

		if (idx < ha->num_pages) {
			ha->ts[idx].t_poll_done   = t_poll;
			ha->ts[idx].t_read_done   = t_read;
			ha->ts[idx].t_ioctl_start = t_ioctl_s;
			ha->ts[idx].t_ioctl_done  = t_ioctl_d;
		}
	}

	munmap(src_page, ha->page_size);
	return NULL;
}

/* ------------------------------------------------------------------ */
/*  BPF setup / readback                                               */
/* ------------------------------------------------------------------ */

static struct overhead_kprobe_bpf *bpf_setup(uint32_t f_tid, uint32_t h_tid)
{
	struct overhead_kprobe_bpf *skel;

	skel = overhead_kprobe_bpf__open();
	if (!skel) {
		fprintf(stderr, "  error: failed to open BPF skeleton\n");
		return NULL;
	}

	skel->rodata->target_tgid = getpid();

	if (overhead_kprobe_bpf__load(skel)) {
		fprintf(stderr, "  error: BPF load failed: %s\n",
			strerror(errno));
		overhead_kprobe_bpf__destroy(skel);
		return NULL;
	}

	skel->bss->faulter_tid = f_tid;
	skel->bss->handler_tid = h_tid;

	if (overhead_kprobe_bpf__attach(skel)) {
		fprintf(stderr, "  error: BPF attach failed: %s\n",
			strerror(errno));
		overhead_kprobe_bpf__destroy(skel);
		return NULL;
	}

	return skel;
}

static void bpf_read_timestamps(struct overhead_kprobe_bpf *skel,
				struct fault_ts *ts, void *region,
				size_t num_pages, size_t page_size)
{
	int map_fd = bpf_map__fd(skel->maps.kernel_ts);
	int found = 0, missing = 0;

	for (size_t i = 0; i < num_pages; i++) {
		uint64_t addr = (uint64_t)((unsigned long)region +
					   i * page_size);
		struct kernel_fault_ts kts;

		if (bpf_map_lookup_elem(map_fd, &addr, &kts) == 0) {
			ts[i].t_huf_entry        = kts.t_huf_entry;
			ts[i].t_huf_return       = kts.t_huf_return;
			ts[i].t_wake             = kts.t_wake;
			ts[i].t_sched_out_faulter = kts.t_sched_out_faulter;
			ts[i].t_sched_in_handler  = kts.t_sched_in_handler;
			ts[i].t_sched_in_faulter  = kts.t_sched_in_faulter;
			ts[i].t_mfill_entry      = kts.t_mfill_entry;
			ts[i].t_sched_waking_handler = kts.t_sched_waking_handler;
			ts[i].t_sched_waking_faulter = kts.t_sched_waking_faulter;
			ts[i].t_mfill_install_pte = kts.t_mfill_install_pte;
			ts[i].t_read_entry       = kts.t_read_entry;
			ts[i].t_read_return      = kts.t_read_return;
			found++;

			bpf_map_delete_elem(map_fd, &addr);
		} else {
			missing++;
		}
	}

	if (missing)
		fprintf(stderr, "  warning: %d/%zu faults missing "
			"kernel timestamps\n", missing, num_pages);
}

/* ------------------------------------------------------------------ */
/*  Baseline benchmark (no uffd — kernel zero-fill)                    */
/* ------------------------------------------------------------------ */

static int64_t run_baseline(size_t num_pages, size_t page_size,
			    size_t warmup, int cpu)
{
	size_t total = num_pages + warmup;
	size_t region_size = total * page_size;
	int64_t *lat;
	int64_t sum = 0;
	void *region;

	pin_to_cpu(cpu);

	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap baseline");
		return 0;
	}
	madvise(region, region_size, MADV_NOHUGEPAGE);

	lat = calloc(num_pages, sizeof(int64_t));

	for (size_t i = 0; i < total; i++) {
		volatile char *p = (volatile char *)region + i * page_size;
		uint64_t before = now_ns();
		char c = *p;
		uint64_t after = now_ns();

		(void)c;
		if (i >= warmup)
			lat[i - warmup] = (int64_t)(after - before);
	}

	qsort(lat, num_pages, sizeof(int64_t), cmp_i64);
	for (size_t i = 0; i < num_pages; i++)
		sum += lat[i];

	int64_t avg = sum / (int64_t)num_pages;

	printf("  Baseline (kernel zero-fill):  avg %ld ns   p50 %ld ns   "
	       "p99 %ld ns   min %ld ns   max %ld ns\n",
	       (long)avg, (long)lat[num_pages / 2],
	       (long)lat[(size_t)(num_pages * 0.99)],
	       (long)lat[0], (long)lat[num_pages - 1]);

	munmap(region, region_size);
	free(lat);
	return avg;
}

/* ------------------------------------------------------------------ */
/*  Phase definitions                                                  */
/* ------------------------------------------------------------------ */

static const char *phase_names[NPHASES] = {
	"Kernel fault path     (t0->K0)",
	"HUF enqueue + state   (K0->WKh)",
	"wake_up_poll -> sched  (WKh->SO)",
	"Ctx switch ->handler  (SO->SI)",
	"Handler poll return   (SI->t1)",
	"read() syscall entry  (t1->RE)",
	"uffd msg delivery     (RE->RR)",
	"read() syscall exit   (RR->t2)",
	"User processing       (t2->t3)",
	"ioctl overhead        (t3->MF)",
	"Page alloc + copy     (MF->IP)",
	"PTE install + rmap    (IP->KW)",
	"Wake + ioctl ret      (KW->t4)",
	"Wake processing       (KW->WKf)",
	"IPI + schedule        (WKf->SI)",
	"HUF cleanup           (SI->K1)",
	"Kernel->user          (K1->t5)",
};

static const char *phase_csv[NPHASES] = {
	"kernel_fault_path", "huf_enqueue", "wakeup_poll_to_sched",
	"ctx_switch_to_handler", "handler_poll_return",
	"read_entry", "read_work", "read_exit",
	"user_processing",
	"ioctl_overhead", "page_alloc_copy", "pte_install",
	"wake_ioctl_ret",
	"wake_processing", "ipi_schedule",
	"huf_cleanup", "kernel_to_user",
};

static const char *phase_prefix[NPHASES] = {
	"  1a ", " 1b.1", " 1b.2", " 1b.3", " 1b.4",
	"   2a", "   2b", "   2c",
	"    3",
	"  4a1", "  4a2", "  4a3",
	"   4b",
	"  5a1", "  5a2", "  5a3",
	"   5b",
};

/*
 * Probe boundary types for measurement overhead correction.
 *
 * Each phase is bounded by two timestamps.  A timestamp is either a
 * userspace now_ns() call (0) or a BPF kprobe/tracepoint (1).  The
 * overhead of each measurement point is split ~50/50 between the
 * preceding and following phases.  By knowing the type at each
 * boundary we can compute per-phase corrections.
 *
 * Phase  Start     End        Start  End
 *  0     t0(tmr)   K0(kp)       0    1
 *  1     K0(kp)    WKh(tp)      1    1
 *  2     WKh(tp)   SO(tp)       1    1
 *  3     SO(tp)    SI(tp)       1    1
 *  4     SI(tp)    t1(tmr)      1    0
 *  5     t1(tmr)   RE(kp)       0    1
 *  6     RE(kp)    RR(krp)      1    1
 *  7     RR(krp)   t2(tmr)      1    0
 *  8     t2(tmr)   t3(tmr)      0    0
 *  9     t3(tmr)   MF(kp)       0    1
 * 10     MF(kp)    IP(kp)       1    1
 * 11     IP(kp)    KW(kp)       1    1
 * 12     KW(kp)    t4(tmr)      1    0   (overlapping)
 * 13     KW(kp)    WKf(tp)      1    1
 * 14     WKf(tp)   SI(tp)       1    1
 * 15     SI(tp)    K1(krp)      1    1
 * 16     K1(krp)   t5(tmr)      1    0
 */
static const int start_is_probe[NPHASES] = {
	0, 1, 1, 1, 1,  0, 1, 1,  0, 0, 1, 1,  1, 1, 1, 1, 1
};
static const int end_is_probe[NPHASES] = {
	1, 1, 1, 1, 0,  1, 1, 0,  0, 1, 1, 1,  0, 1, 1, 1, 0
};

/* ------------------------------------------------------------------ */
/*  Probe overhead calibration (unprobed UFFD run)                     */
/* ------------------------------------------------------------------ */

/*
 * Run a quick UFFD benchmark without BPF probes attached.
 * Returns the average per-fault latency.  The difference between this
 * and the BPF-probed total gives us the total probe overhead.
 */
static int64_t run_uffd_calibration(size_t page_size, size_t warmup,
				    int f_cpu, int h_cpu)
{
	size_t num_pages = CALIB_PAGES;
	size_t total = num_pages + warmup;
	size_t region_size = total * page_size;
	struct fault_ts *ts;
	void *region;
	int uffd;
	struct uffdio_api api;
	struct uffdio_register reg;
	pthread_t handler;
	struct handler_args ha;
	int64_t sum = 0;

	pin_to_cpu(f_cpu);

	ts = calloc(total, sizeof(struct fault_ts));
	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap calibration");
		free(ts);
		return 0;
	}
	madvise(region, region_size, MADV_NOHUGEPAGE);

	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0) {
		perror("userfaultfd calibration");
		munmap(region, region_size);
		free(ts);
		return 0;
	}

	api.api = UFFD_API;
	api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &api) < 0) {
		perror("UFFDIO_API");
		goto out;
	}

	reg.range.start = (unsigned long)region;
	reg.range.len   = region_size;
	reg.mode        = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) {
		perror("UFFDIO_REGISTER");
		goto out;
	}

	ha = (struct handler_args){
		.uffd        = uffd,
		.page_size   = page_size,
		.num_pages   = total,
		.region      = region,
		.ts          = ts,
		.cpu         = h_cpu,
		.done        = 0,
		.handler_tid = 0,
	};
	pthread_create(&handler, NULL, uffd_handler_thread, &ha);
	usleep(1000);

	for (size_t i = 0; i < total; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		ts[i].t_fault_start = now_ns();
		char c = *p;
		ts[i].t_fault_done = now_ns();
		(void)c;
	}

	ha.done = 1;
	pthread_join(handler, NULL);

	for (size_t i = warmup; i < total; i++)
		sum += (int64_t)(ts[i].t_fault_done - ts[i].t_fault_start);

out:
	close(uffd);
	munmap(region, region_size);
	free(ts);
	return sum / (int64_t)num_pages;
}

/* ------------------------------------------------------------------ */
/*  UFFD overhead breakdown benchmark                                  */
/* ------------------------------------------------------------------ */

static void run_uffd_breakdown(size_t num_pages, size_t page_size,
			       size_t warmup, int f_cpu, int h_cpu,
			       int use_kprobe, int csv,
			       int64_t baseline_avg, int64_t ctx_switch_ns,
			       int64_t timer_overhead_ns,
			       int64_t probe_overhead_ns)
{
	size_t total = num_pages + warmup;
	size_t region_size = total * page_size;
	struct fault_ts *ts;
	void *region;
	int uffd;
	struct uffdio_api api;
	struct uffdio_register reg;
	pthread_t handler;
	struct handler_args ha;
	struct rusage ru_before, ru_after;
	struct rusage_delta rd;
	struct overhead_kprobe_bpf *skel = NULL;

	int64_t *phase_data = NULL;
	int64_t *phase_lat[NPHASES];
	int64_t *total_lat;

	pin_to_cpu(f_cpu);

	ts = calloc(total, sizeof(struct fault_ts));
	total_lat = calloc(num_pages, sizeof(int64_t));
	if (use_kprobe) {
		phase_data = calloc((size_t)NPHASES * num_pages,
				    sizeof(int64_t));
		for (int p = 0; p < NPHASES; p++)
			phase_lat[p] = &phase_data[(size_t)p * num_pages];
	}

	/* Set up the anonymous mmap region */
	region = mmap(NULL, region_size, PROT_READ | PROT_WRITE,
		      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (region == MAP_FAILED) {
		perror("mmap");
		goto out;
	}
	madvise(region, region_size, MADV_NOHUGEPAGE);

	/* Create and configure userfaultfd */
	uffd = syscall(SYS_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd < 0) {
		perror("userfaultfd");
		goto out_unmap;
	}

	api.api = UFFD_API;
	api.features = 0;
	if (ioctl(uffd, UFFDIO_API, &api) < 0) {
		perror("UFFDIO_API");
		goto out_close;
	}

	reg.range.start = (unsigned long)region;
	reg.range.len   = region_size;
	reg.mode        = UFFDIO_REGISTER_MODE_MISSING;
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) < 0) {
		perror("UFFDIO_REGISTER");
		goto out_close;
	}

	/* Launch handler thread */
	ha = (struct handler_args){
		.uffd        = uffd,
		.page_size   = page_size,
		.num_pages   = total,
		.region      = region,
		.ts          = ts,
		.cpu         = h_cpu,
		.done        = 0,
		.handler_tid = 0,
	};
	pthread_create(&handler, NULL, uffd_handler_thread, &ha);
	usleep(1000);

	/* Set up and attach BPF probes */
	if (use_kprobe) {
		skel = bpf_setup((uint32_t)syscall(SYS_gettid),
				 ha.handler_tid);
		if (!skel) {
			fprintf(stderr, "  BPF setup failed, "
				"skipping phase breakdown\n");
			use_kprobe = 0;
		}
	}

	/* Fault phase: touch each page sequentially */
	getrusage(RUSAGE_SELF, &ru_before);

	for (size_t i = 0; i < total; i++) {
		volatile char *p = (volatile char *)region + i * page_size;

		ts[i].t_fault_start = now_ns();
		char c = *p;
		ts[i].t_fault_done = now_ns();
		(void)c;
	}

	getrusage(RUSAGE_SELF, &ru_after);

	/* Shut down handler */
	ha.done = 1;
	pthread_join(handler, NULL);
	close(uffd);

	/* Read BPF kernel timestamps */
	if (skel)
		bpf_read_timestamps(skel, ts, region, total, page_size);

	/* Verify page contents */
	int errors = 0;

	for (size_t i = 0; i < total; i++) {
		unsigned char *p = (unsigned char *)region + i * page_size;

		if (p[0] != FILL_BYTE) {
			errors++;
			if (errors <= 3)
				fprintf(stderr, "  page %zu: got 0x%02x "
					"expected 0x%02x\n",
					i, p[0], FILL_BYTE);
		}
	}
	if (errors)
		fprintf(stderr, "  VERIFICATION FAILED: %d pages\n", errors);

	/* Compute per-fault latencies (skip warmup pages) */
	for (size_t i = warmup; i < total; i++) {
		size_t j = i - warmup;
		struct fault_ts *t = &ts[i];

		total_lat[j] = (int64_t)(t->t_fault_done - t->t_fault_start);

		if (!skel)
			continue;

		/* 17 sub-phases; all except 4b (index 12) sum to total */
		phase_lat[0][j]  = phase_delta(t->t_huf_entry, t->t_fault_start);
		phase_lat[1][j]  = phase_delta(t->t_sched_waking_handler, t->t_huf_entry);
		phase_lat[2][j]  = phase_delta(t->t_sched_out_faulter, t->t_sched_waking_handler);
		phase_lat[3][j]  = phase_delta(t->t_sched_in_handler, t->t_sched_out_faulter);
		phase_lat[4][j]  = phase_delta(t->t_poll_done, t->t_sched_in_handler);
		phase_lat[5][j]  = phase_delta(t->t_read_entry, t->t_poll_done);
		phase_lat[6][j]  = phase_delta(t->t_read_return, t->t_read_entry);
		phase_lat[7][j]  = phase_delta(t->t_read_done, t->t_read_return);
		phase_lat[8][j]  = phase_delta(t->t_ioctl_start, t->t_read_done);
		phase_lat[9][j]  = phase_delta(t->t_mfill_entry, t->t_ioctl_start);
		phase_lat[10][j] = phase_delta(t->t_mfill_install_pte, t->t_mfill_entry);
		phase_lat[11][j] = phase_delta(t->t_wake, t->t_mfill_install_pte);
		phase_lat[12][j] = phase_delta(t->t_ioctl_done, t->t_wake);
		phase_lat[13][j] = phase_delta(t->t_sched_waking_faulter, t->t_wake);
		phase_lat[14][j] = phase_delta(t->t_sched_in_faulter, t->t_sched_waking_faulter);
		phase_lat[15][j] = phase_delta(t->t_huf_return, t->t_sched_in_faulter);
		phase_lat[16][j] = phase_delta(t->t_fault_done, t->t_huf_return);
	}

	/* Compute total average for percentage calculation */
	int64_t total_sum = 0;

	for (size_t i = 0; i < num_pages; i++)
		total_sum += total_lat[i];
	int64_t total_avg = total_sum / (int64_t)num_pages;

	/*
	 * Compute per-phase measurement overhead corrections.
	 *
	 * probe_overhead_ns arrives as the unprobed UFFD total latency
	 * (0 if not calibrated).  Convert it to per-probe overhead by
	 * comparing against this round's probed total:
	 *
	 *   per_probe = (probed_total - unprobed_total) / NUM_PROBE_HITS
	 *
	 * Each phase boundary inserts overhead: ~timer_overhead for a
	 * userspace now_ns() call, ~per_probe for a BPF kprobe/
	 * tracepoint.  We approximate the split as 50/50: half the
	 * overhead of each measurement point is attributed to the
	 * preceding phase, half to the following phase.
	 *
	 * correction[i] = overhead(start_boundary)/2 + overhead(end_boundary)/2
	 */
	int64_t per_probe = 0;
	int64_t phase_corr[NPHASES];
	int64_t total_corr = 0;

	if (skel && probe_overhead_ns > 0 && total_avg > probe_overhead_ns)
		per_probe = (total_avg - probe_overhead_ns) / NUM_PROBE_HITS;

	for (int p = 0; p < NPHASES; p++) {
		int64_t sc = start_is_probe[p] ? per_probe
					       : timer_overhead_ns;
		int64_t ec = end_is_probe[p] ? per_probe
					     : timer_overhead_ns;
		phase_corr[p] = (sc + ec) / 2;
		if (p != 12) /* 4b overlaps, exclude from total */
			total_corr += phase_corr[p];
	}

	/* CSV output mode: one row per round with corrected averages */
	if (csv) {
		int64_t phase_sum[NPHASES] = {};

		if (skel)
			for (int p = 0; p < NPHASES; p++)
				for (size_t i = 0; i < num_pages; i++)
					phase_sum[p] += phase_lat[p][i];

		printf("%ld", (long)clamp_pos(total_avg - total_corr));
		if (skel)
			for (int p = 0; p < NPHASES; p++) {
				int64_t raw = phase_sum[p] /
					      (int64_t)num_pages;
				printf(",%ld",
				       (long)clamp_pos(raw - phase_corr[p]));
			}
		printf(",%ld,%ld",
		       (long)timer_overhead_ns, (long)per_probe);
		printf("\n");
		goto out_stats_done;
	}

	/* Human-readable output */
	rd = rusage_diff(&ru_before, &ru_after);

	printf("  UFFD overhead breakdown (%zu pages, %zu warmup, "
	       "CPUs %d+%d%s):\n\n",
	       num_pages, warmup, f_cpu, h_cpu,
	       skel ? ", BPF probes" : "");

	if (skel) {
		int64_t corr_total_avg = clamp_pos(total_avg - total_corr);

		printf("  %-40s %8s %8s %8s %8s %8s %7s %8s\n",
		       "Phase", "raw(ns)", "p50", "p99", "min", "max",
		       "%total", "corr");
		printf("  ─────────────────────────────────────"
		       "─── ──────── ──────── ──────── "
		       "──────── ──────── ─────── ────────\n");

		for (int p = 0; p < NPHASES; p++) {
			struct phase_stat s = compute_stat(phase_lat[p],
							   num_pages,
							   total_avg);
			int64_t corr = clamp_pos(s.avg - phase_corr[p]);

			printf("  %s. %-33s %8ld %8ld %8ld %8ld %8ld"
			       " %6.1f%% %7ld%s\n",
			       phase_prefix[p], phase_names[p],
			       (long)s.avg, (long)s.p50, (long)s.p99,
			       (long)s.min, (long)s.max, s.pct,
			       (long)corr,
			       p == 12 ? " *" : "");
		}

		printf("  ─────────────────────────────────────"
		       "─── ──────── ──────── ──────── "
		       "──────── ──────── ─────── ────────\n");

		{
			struct phase_stat s = compute_stat(total_lat,
							   num_pages,
							   total_avg);
			printf("  %-40s %8ld %8ld %8ld %8ld %8ld %6.1f%% %7ld\n",
			       "Total (end-to-end)",
			       (long)s.avg, (long)s.p50, (long)s.p99,
			       (long)s.min, (long)s.max, s.pct,
			       (long)corr_total_avg);
		}

		printf("\n  * Phase 4b overlaps with 5a1-5b "
		       "(handler/faulter run in parallel)\n");
		printf("  * corr = avg - measurement overhead "
		       "(timer: %ld ns, probe: %ld ns per hit)\n",
		       (long)timer_overhead_ns, (long)per_probe);
	}

	printf("\n");

	/* Context switch and fault counts */
	printf("  Context switches:  voluntary %ld  involuntary %ld\n",
	       rd.vol_csw, rd.invol_csw);
	printf("  Page faults:       minor %ld  major %ld\n",
	       rd.minflt, rd.majflt);
	printf("  Per-fault cost:    %ld ns/fault  (%.0f faults/sec)\n",
	       (long)total_avg,
	       num_pages / (total_sum / 1e9));

	if (baseline_avg > 0)
		printf("  vs baseline:       %.1fx overhead  "
		       "(baseline: %ld ns/fault)\n",
		       (double)total_avg / baseline_avg,
		       (long)baseline_avg);

	if (ctx_switch_ns > 0) {
		printf("  Ctx switch cost:   %ld ns/switch  "
		       "(~%ld ns/fault from 2 switches, %.0f%% of total)\n",
		       (long)ctx_switch_ns,
		       (long)(ctx_switch_ns * 2),
		       200.0 * ctx_switch_ns / total_avg);
	}

	if (skel) {
		printf("\n  What each sub-phase includes:\n");
		printf("    1a.  Page fault exception -> handle_mm_fault "
		       "-> handle_userfault entry\n");
		printf("   1b.1  HUF: enqueue msg, set TASK_KILLABLE "
		       "(before wake_up_poll)\n");
		printf("   1b.2  wake_up_poll -> try_to_wake_up "
		       "-> schedule() (sched_waking)\n");
		printf("   1b.3  Exact faulter->handler context switch "
		       "(sched_switch)\n");
		printf("   1b.4  Handler CPU: poll() returns to "
		       "userspace\n");
		printf("    2a.  read() syscall entry: "
		       "sys_read -> vfs_read -> dispatch\n");
		printf("    2b.  userfaultfd_read_iter: "
		       "ctx_read, refile, copy_to_iter\n");
		printf("    2c.  read() syscall exit: "
		       "VFS return path -> userspace\n");
		printf("     3.  Userspace: parse fault address, "
		       "prepare ioctl args\n");
		printf("   4a1.  ioctl(UFFDIO_COPY) syscall entry, "
		       "VMA lock acquisition\n");
		printf("   4a2.  mfill_atomic_pte_copy: "
		       "vma_alloc_folio, copy_from_user\n");
		printf("   4a3.  mfill_atomic_install_pte: "
		       "PTE lock, set_pte_at, rmap, TLB\n");
		printf("    4b.  __wake_userfault -> ioctl return "
		       "(parallel to 5a/5b)\n");
		printf("   5a1.  __wake_userfault: spinlock, "
		       "wake_up -> try_to_wake_up\n");
		printf("   5a2.  IPI delivery + runqueue wait "
		       "+ scheduler dispatch\n");
		printf("   5a3.  handle_userfault post-wake cleanup, "
		       "__set_current_state\n");
		printf("    5b.  Fault path unwinds through kernel, "
		       "returns to userspace\n");
	} else {
		printf("\n  Tip: use -k for 17-phase BPF-instrumented "
		       "breakdown\n");
	}

out_stats_done:
	munmap(region, region_size);
out_close:
out_unmap:
out:
	if (skel)
		overhead_kprobe_bpf__destroy(skel);
	free(phase_data);
	free(total_lat);
	free(ts);
}

/* ------------------------------------------------------------------ */
/*  Main                                                               */
/* ------------------------------------------------------------------ */

static void usage(const char *prog)
{
	fprintf(stderr,
		"Usage: %s [-n pages] [-w warmup] [-r rounds] "
		"[-c fault_cpu,handler_cpu] [-k] [-C] [-o file]\n\n"
		"  -n  Pages to fault per round (default: 4096)\n"
		"  -w  Warmup pages to skip (default: 64)\n"
		"  -r  Rounds to run (default: 3)\n"
		"  -c  CPU pinning: fault_cpu,handler_cpu (default: 0,1)\n"
		"  -k  Enable BPF instrumentation (17 sub-phases)\n"
		"  -C  CSV output (one row per round, averages)\n"
		"  -o  Write CSV output to file (default: stdout)\n",
		prog);
}

int main(int argc, char **argv)
{
	size_t num_pages = 4096;
	size_t warmup = 64;
	int rounds = 3;
	int f_cpu = 0, h_cpu = 1;
	int csv = 0, use_kprobe = 0;
	const char *csv_path = NULL;
	long page_size = sysconf(_SC_PAGESIZE);
	int opt;

	while ((opt = getopt(argc, argv, "n:w:r:c:kCo:h")) != -1) {
		switch (opt) {
		case 'n':
			num_pages = strtoul(optarg, NULL, 0);
			break;
		case 'w':
			warmup = strtoul(optarg, NULL, 0);
			break;
		case 'r':
			rounds = atoi(optarg);
			break;
		case 'c':
			if (sscanf(optarg, "%d,%d", &f_cpu, &h_cpu) != 2) {
				fprintf(stderr, "Bad -c format, use: cpu,cpu\n");
				return 1;
			}
			break;
		case 'k':
			use_kprobe = 1;
			break;
		case 'C':
			csv = 1;
			break;
		case 'o':
			csv_path = optarg;
			csv = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			return opt == 'h' ? 0 : 1;
		}
	}

	if (!csv) {
		uint64_t timer_overhead = calibrate_timer();
		int64_t probe_overhead = 0;

		printf("UFFD overhead breakdown benchmark\n");
		printf("  Pages: %zu  Warmup: %zu  Rounds: %d  "
		       "Page size: %ld\n", num_pages, warmup, rounds,
		       page_size);
		printf("  CPUs: faulter=%d  handler=%d\n", f_cpu, h_cpu);
		printf("  Mode: %s\n",
		       use_kprobe ? "BPF-instrumented (17 sub-phases)"
				  : "userspace timestamps only");
		printf("  Timer overhead: %lu ns/call\n",
		       (unsigned long)timer_overhead);

		printf("\n  Calibrating context switch latency...\n");
		int64_t ctx_ns = measure_ctx_switch(f_cpu, h_cpu);
		printf("  Context switch (pipe ping-pong): "
		       "%ld ns/switch\n", (long)ctx_ns);

		if (use_kprobe) {
			printf("\n  Calibrating probe overhead "
			       "(%d pages, no BPF)...\n", CALIB_PAGES);
			int64_t unprobed = run_uffd_calibration(
				page_size, warmup, f_cpu, h_cpu);
			printf("  Unprobed UFFD latency: "
			       "%ld ns/fault\n", (long)unprobed);
			/*
			 * probe_overhead is computed per-round below
			 * using each round's probed total vs this
			 * unprobed baseline.  Store unprobed for now.
			 */
			probe_overhead = unprobed;
		}
		printf("\n");

		for (int r = 0; r < rounds; r++) {
			printf("--- Round %d/%d ---\n\n", r + 1, rounds);

			int64_t baseline_avg = run_baseline(num_pages,
							    page_size,
							    warmup, f_cpu);
			printf("\n");

			run_uffd_breakdown(num_pages, page_size, warmup,
					   f_cpu, h_cpu, use_kprobe, 0,
					   baseline_avg, ctx_ns,
					   (int64_t)timer_overhead,
					   probe_overhead);
			printf("\n");
		}
	} else {
		uint64_t timer_overhead = calibrate_timer();
		int64_t unprobed_avg = 0;
		FILE *csv_fp = stdout;

		if (use_kprobe)
			unprobed_avg = run_uffd_calibration(
				page_size, warmup, f_cpu, h_cpu);

		if (csv_path) {
			csv_fp = fopen(csv_path, "w");
			if (!csv_fp) {
				perror(csv_path);
				return 1;
			}
			/* Redirect stdout so printf in
			 * run_uffd_breakdown writes to the file */
			if (dup2(fileno(csv_fp), STDOUT_FILENO) < 0) {
				perror("dup2");
				fclose(csv_fp);
				return 1;
			}
			fclose(csv_fp);
			fprintf(stderr,
				"Writing CSV to %s\n", csv_path);
		}

		/* Print CSV header */
		printf("total_avg_ns");
		if (use_kprobe)
			for (int p = 0; p < NPHASES; p++)
				printf(",%s_avg_ns", phase_csv[p]);
		if (use_kprobe)
			printf(",timer_overhead_ns,probe_overhead_ns");
		printf("\n");

		for (int r = 0; r < rounds; r++)
			run_uffd_breakdown(num_pages, page_size, warmup,
					   f_cpu, h_cpu, use_kprobe, 1,
					   0, 0,
					   (int64_t)timer_overhead,
					   unprobed_avg);
	}

	return 0;
}
