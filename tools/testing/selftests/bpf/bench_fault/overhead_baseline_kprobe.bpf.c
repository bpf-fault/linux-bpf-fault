// SPDX-License-Identifier: GPL-2.0-only
/*
 * overhead_baseline_kprobe.bpf.c — BPF probes for baseline fault overhead.
 *
 * Instruments the kernel's anonymous read-fault zero-page path
 * (no uffd/bpf_fault) to capture timestamps at key points:
 *
 *   kprobe/handle_mm_fault    — top-level fault entry
 *   kretprobe/handle_mm_fault — top-level fault return
 *   kprobe/do_pte_missing     — PTE missing handler entry
 *
 * Timeline for a single anonymous read fault (zero-page map):
 *
 *   t0: read page -> FAULT
 *   HM: handle_mm_fault entry
 *         [inlined: __handle_mm_fault: PGD/P4D/PUD/PMD walk]
 *         [inlined: handle_pte_fault]
 *   PM:   do_pte_missing entry
 *         [inlined: do_anonymous_page]
 *           pte_alloc()
 *           pte_mkspecial(pfn_pte(zero_pfn))
 *           pte_offset_map_lock()
 *           set_ptes()
 *           pte_unmap_unlock()
 *   HR: handle_mm_fault return
 *   t5: back to userspace
 *
 * This is the kernel's cheapest anonymous fault path — the same
 * operation that bpf_fault replaces with a BPF-controlled page fill.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct baseline_fault_ts {
	__u64 t_hmf_entry;	/* handle_mm_fault entry  */
	__u64 t_hmf_return;	/* handle_mm_fault return */
	__u64 t_pte_missing;	/* do_pte_missing entry   */
};

/* Per-fault kernel timestamps, keyed by page-aligned fault address */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct baseline_fault_ts);
} kernel_ts SEC(".maps");

/* Per-task scratch: tid -> fault address (for kretprobe correlation) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} task_addr SEC(".maps");

const volatile __u32 target_tgid = 0;

/* Address range filter — only track faults in the benchmark region */
volatile __u64 region_start = 0;
volatile __u64 region_end = 0;

SEC("kprobe/handle_mm_fault")
int BPF_KPROBE(hmf_entry, struct vm_area_struct *vma,
	       unsigned long address, unsigned int flags)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 tid;
	__u64 addr;
	struct baseline_fault_ts ts = {};

	if (tgid != target_tgid)
		return 0;

	addr = address & ~(__u64)0xFFF;
	if (addr < region_start || addr >= region_end)
		return 0;

	ts.t_hmf_entry = bpf_ktime_get_ns();
	bpf_map_update_elem(&kernel_ts, &addr, &ts, BPF_ANY);

	tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&task_addr, &tid, &addr, BPF_ANY);

	return 0;
}

SEC("kretprobe/handle_mm_fault")
int BPF_KRETPROBE(hmf_return, vm_fault_t ret)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 tid;
	__u64 *addr;
	struct baseline_fault_ts *ts;

	if (tgid != target_tgid)
		return 0;

	tid = (__u32)bpf_get_current_pid_tgid();
	addr = bpf_map_lookup_elem(&task_addr, &tid);
	if (!addr)
		return 0;

	ts = bpf_map_lookup_elem(&kernel_ts, addr);
	if (ts)
		ts->t_hmf_return = bpf_ktime_get_ns();

	bpf_map_delete_elem(&task_addr, &tid);
	return 0;
}

SEC("kprobe/do_pte_missing")
int BPF_KPROBE(pm_entry, struct vm_fault *vmf)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 tid;
	__u64 *addr;
	struct baseline_fault_ts *ts;

	if (tgid != target_tgid)
		return 0;

	tid = (__u32)bpf_get_current_pid_tgid();
	addr = bpf_map_lookup_elem(&task_addr, &tid);
	if (!addr)
		return 0;

	ts = bpf_map_lookup_elem(&kernel_ts, addr);
	if (ts)
		ts->t_pte_missing = bpf_ktime_get_ns();

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
