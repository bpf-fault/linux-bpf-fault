// SPDX-License-Identifier: GPL-2.0-only
/*
 * overhead_kprobe.bpf.c — BPF probes for UFFD overhead instrumentation.
 *
 * Attaches to kernel functions and tracepoints to capture timestamps
 * at key points in the userfaultfd fault-handling path:
 *
 *   kprobe/handle_userfault       — faulting thread enters UFFD handling
 *   kretprobe/handle_userfault    — faulting thread returns after wake
 *   kprobe/__wake_userfault       — handler thread wakes the faulter
 *   tp_btf/sched_switch           — exact context switch timestamps
 *   tp_btf/sched_waking           — wake-to-runqueue timestamps
 *   kprobe/mfill_atomic_pte_copy  — page copy function entry
 *   kprobe/mfill_atomic_install_pte — PTE install function entry
 *   kprobe/userfaultfd_read_iter  — read() enters uffd handler
 *   kretprobe/userfaultfd_read_iter — read() leaves uffd handler
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct kernel_fault_ts {
	__u64 t_huf_entry;		/* handle_userfault entry        */
	__u64 t_huf_return;		/* handle_userfault return       */
	__u64 t_wake;			/* __wake_userfault entry        */
	__u64 t_sched_out_faulter;	/* faulter sched_switch out      */
	__u64 t_sched_in_handler;	/* handler sched_switch in       */
	__u64 t_sched_in_faulter;	/* faulter sched_switch in       */
	__u64 t_mfill_entry;		/* mfill_atomic_pte_copy entry   */
	__u64 t_sched_waking_handler;	/* sched_waking for handler      */
	__u64 t_sched_waking_faulter;	/* sched_waking for faulter      */
	__u64 t_mfill_install_pte;	/* mfill_atomic_install_pte      */
	__u64 t_read_entry;		/* userfaultfd_read_iter entry   */
	__u64 t_read_return;		/* userfaultfd_read_iter return  */
};

/* Per-fault kernel timestamps, keyed by page-aligned fault address */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct kernel_fault_ts);
} kernel_ts SEC(".maps");

/* Per-task scratch: tid -> fault address (for kretprobe correlation) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} task_addr SEC(".maps");

const volatile __u32 target_tgid = 0;

volatile __u32 faulter_tid = 0;
volatile __u32 handler_tid = 0;
volatile __u64 active_fault_addr = 0;

SEC("kprobe/handle_userfault")
int BPF_KPROBE(huf_entry, struct vm_fault *vmf, unsigned long reason)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 tid;
	__u64 addr;
	struct kernel_fault_ts ts = {};

	if (tgid != target_tgid)
		return 0;

	addr = BPF_CORE_READ(vmf, address) & ~(__u64)0xFFF;

	ts.t_huf_entry = bpf_ktime_get_ns();
	bpf_map_update_elem(&kernel_ts, &addr, &ts, BPF_ANY);

	tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&task_addr, &tid, &addr, BPF_ANY);

	active_fault_addr = addr;
	return 0;
}

SEC("kretprobe/handle_userfault")
int BPF_KRETPROBE(huf_return, vm_fault_t ret)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 tid;
	__u64 *addr;
	struct kernel_fault_ts *ts;

	if (tgid != target_tgid)
		return 0;

	tid = (__u32)bpf_get_current_pid_tgid();
	addr = bpf_map_lookup_elem(&task_addr, &tid);
	if (!addr)
		return 0;

	ts = bpf_map_lookup_elem(&kernel_ts, addr);
	if (ts)
		ts->t_huf_return = bpf_ktime_get_ns();

	active_fault_addr = 0;
	bpf_map_delete_elem(&task_addr, &tid);
	return 0;
}

SEC("kprobe/__wake_userfault")
int BPF_KPROBE(wake_entry, struct userfaultfd_ctx *uf_ctx,
	       struct userfaultfd_wake_range *range)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 addr;
	struct kernel_fault_ts *ts;

	if (tgid != target_tgid)
		return 0;

	addr = BPF_CORE_READ(range, start) & ~(__u64)0xFFF;

	ts = bpf_map_lookup_elem(&kernel_ts, &addr);
	if (ts)
		ts->t_wake = bpf_ktime_get_ns();

	return 0;
}

SEC("tp_btf/sched_switch")
int BPF_PROG(sched_switch_prog, bool preempt,
	     struct task_struct *prev, struct task_struct *next)
{
	__u32 prev_pid, next_pid, f_tid, h_tid;
	struct kernel_fault_ts *ts;
	__u64 fault_addr, now;

	prev_pid = BPF_CORE_READ(prev, pid);
	next_pid = BPF_CORE_READ(next, pid);
	f_tid = faulter_tid;
	h_tid = handler_tid;

	if (prev_pid != f_tid && next_pid != f_tid && next_pid != h_tid)
		return 0;

	fault_addr = active_fault_addr;
	if (!fault_addr)
		return 0;

	ts = bpf_map_lookup_elem(&kernel_ts, &fault_addr);
	if (!ts)
		return 0;

	now = bpf_ktime_get_ns();

	if (prev_pid == f_tid && !ts->t_sched_out_faulter)
		ts->t_sched_out_faulter = now;

	if (next_pid == h_tid && !ts->t_sched_in_handler)
		ts->t_sched_in_handler = now;

	if (next_pid == f_tid && ts->t_wake && !ts->t_sched_in_faulter)
		ts->t_sched_in_faulter = now;

	return 0;
}

/*
 * sched_waking — captures the moment try_to_wake_up() fires for a task.
 *
 * For the handler: fires from wake_up_poll() inside handle_userfault,
 * splitting HUF setup into "enqueue + state" vs "wake processing".
 *
 * For the faulter: fires from __wake_userfault → wake_up path,
 * splitting the reverse context switch into "wake processing"
 * (lock + IPI send) vs "IPI + scheduling latency".
 */
SEC("tp_btf/sched_waking")
int BPF_PROG(sched_waking_prog, struct task_struct *p)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 waking_pid, f_tid, h_tid;
	struct kernel_fault_ts *ts;
	__u64 fault_addr, now;

	if (tgid != target_tgid)
		return 0;

	waking_pid = BPF_CORE_READ(p, pid);
	f_tid = faulter_tid;
	h_tid = handler_tid;

	if (waking_pid != f_tid && waking_pid != h_tid)
		return 0;

	fault_addr = active_fault_addr;
	if (!fault_addr)
		return 0;

	ts = bpf_map_lookup_elem(&kernel_ts, &fault_addr);
	if (!ts)
		return 0;

	now = bpf_ktime_get_ns();

	if (waking_pid == h_tid && !ts->t_sched_waking_handler)
		ts->t_sched_waking_handler = now;

	if (waking_pid == f_tid && ts->t_wake && !ts->t_sched_waking_faulter)
		ts->t_sched_waking_faulter = now;

	return 0;
}

SEC("kprobe/mfill_atomic_pte_copy")
int BPF_KPROBE(mfill_pte_copy, pmd_t *dst_pmd,
	       struct vm_area_struct *dst_vma,
	       unsigned long dst_addr)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 addr;
	struct kernel_fault_ts *ts;

	if (tgid != target_tgid)
		return 0;

	addr = dst_addr & ~(__u64)0xFFF;

	ts = bpf_map_lookup_elem(&kernel_ts, &addr);
	if (ts)
		ts->t_mfill_entry = bpf_ktime_get_ns();

	return 0;
}

/*
 * mfill_atomic_install_pte — marks the start of PTE installation,
 * splitting page alloc+copy from the PTE lock+install+rmap work.
 */
SEC("kprobe/mfill_atomic_install_pte")
int BPF_KPROBE(mfill_install_pte, pmd_t *dst_pmd,
	       struct vm_area_struct *dst_vma,
	       unsigned long dst_addr)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 addr;
	struct kernel_fault_ts *ts;

	if (tgid != target_tgid)
		return 0;

	addr = dst_addr & ~(__u64)0xFFF;

	ts = bpf_map_lookup_elem(&kernel_ts, &addr);
	if (ts)
		ts->t_mfill_install_pte = bpf_ktime_get_ns();

	return 0;
}

/*
 * userfaultfd_read_iter — the .read_iter file_operations callback.
 *
 * Splitting the read() syscall into:
 *   syscall entry  (t1 → RE):  VFS dispatch overhead
 *   uffd work      (RE → RR):  userfaultfd_ctx_read + copy_to_iter
 *   syscall exit   (RR → t2):  VFS return + syscall exit path
 */
SEC("kprobe/userfaultfd_read_iter")
int BPF_KPROBE(uffd_read_iter_entry, struct kiocb *iocb, struct iov_iter *to)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct kernel_fault_ts *ts;
	__u64 fault_addr;

	if (tid != handler_tid)
		return 0;

	fault_addr = active_fault_addr;
	if (!fault_addr)
		return 0;

	ts = bpf_map_lookup_elem(&kernel_ts, &fault_addr);
	if (ts)
		ts->t_read_entry = bpf_ktime_get_ns();

	/* Store fault addr for kretprobe correlation */
	bpf_map_update_elem(&task_addr, &tid, &fault_addr, BPF_ANY);

	return 0;
}

SEC("kretprobe/userfaultfd_read_iter")
int BPF_KRETPROBE(uffd_read_iter_return, ssize_t ret)
{
	__u32 tid = (__u32)bpf_get_current_pid_tgid();
	struct kernel_fault_ts *ts;
	__u64 *addr;

	if (tid != handler_tid)
		return 0;

	addr = bpf_map_lookup_elem(&task_addr, &tid);
	if (!addr)
		return 0;

	ts = bpf_map_lookup_elem(&kernel_ts, addr);
	if (ts)
		ts->t_read_return = bpf_ktime_get_ns();

	bpf_map_delete_elem(&task_addr, &tid);

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
