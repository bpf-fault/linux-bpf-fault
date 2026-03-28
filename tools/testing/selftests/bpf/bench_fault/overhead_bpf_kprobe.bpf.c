// SPDX-License-Identifier: GPL-2.0-only
/*
 * overhead_bpf_kprobe.bpf.c — BPF probes for bpf_fault overhead.
 *
 * Instruments the bpf_fault page fault handling path to capture
 * timestamps at key points:
 *
 *   kprobe/handle_bpf_fault         — bpf_fault handler entry
 *   kretprobe/handle_bpf_fault      — bpf_fault handler return
 *   kprobe/bpf_fault_lock_vma       — VMA re-lock (after BPF program)
 *   kprobe/mfill_atomic_install_pte — PTE installation
 *
 * Timeline for a single bpf_fault MISSING fault:
 *
 *   t0: read page -> FAULT
 *       kernel: handle_mm_fault -> do_anonymous_page
 *   BF:   handle_bpf_fault entry
 *           release_fault_lock()
 *           folio_alloc()
 *           kmap_local_folio()
 *           [BPF struct_ops program fills page]
 *           kunmap_local()
 *           flush_dcache_folio()
 *           __folio_mark_uptodate()
 *   LV:   bpf_fault_lock_vma()
 *           mem_cgroup_charge()
 *           bpf_fault_alloc_pmd()
 *   IP:   mfill_atomic_install_pte()
 *           bpf_fault_unlock_vma()
 *   BR: handle_bpf_fault return
 *   t5: back to userspace
 *
 * Note: bpf_fault_lock_vma is a static function in mm/bpf_fault.c;
 * probing it requires CONFIG_KALLSYMS_ALL=y.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

struct bpf_overhead_ts {
	__u64 t_bf_entry;	/* handle_bpf_fault entry        */
	__u64 t_bf_return;	/* handle_bpf_fault return       */
	__u64 t_lock_vma;	/* bpf_fault_lock_vma entry      */
	__u64 t_install_pte;	/* mfill_atomic_install_pte entry */
};

/* Per-fault kernel timestamps, keyed by page-aligned fault address */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct bpf_overhead_ts);
} kernel_ts SEC(".maps");

/* Per-task scratch: tid -> fault address (for kretprobe correlation) */
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 64);
	__type(key, __u32);
	__type(value, __u64);
} task_addr SEC(".maps");

const volatile __u32 target_tgid = 0;

SEC("kprobe/handle_bpf_fault")
int BPF_KPROBE(bf_entry, struct vm_fault *vmf, bool can_complete)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 tid;
	__u64 addr;
	struct bpf_overhead_ts ts = {};

	if (tgid != target_tgid)
		return 0;

	addr = BPF_CORE_READ(vmf, address) & ~(__u64)0xFFF;

	ts.t_bf_entry = bpf_ktime_get_ns();
	bpf_map_update_elem(&kernel_ts, &addr, &ts, BPF_ANY);

	tid = (__u32)bpf_get_current_pid_tgid();
	bpf_map_update_elem(&task_addr, &tid, &addr, BPF_ANY);

	return 0;
}

SEC("kretprobe/handle_bpf_fault")
int BPF_KRETPROBE(bf_return, vm_fault_t ret)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u32 tid;
	__u64 *addr;
	struct bpf_overhead_ts *ts;

	if (tgid != target_tgid)
		return 0;

	tid = (__u32)bpf_get_current_pid_tgid();
	addr = bpf_map_lookup_elem(&task_addr, &tid);
	if (!addr)
		return 0;

	ts = bpf_map_lookup_elem(&kernel_ts, addr);
	if (ts)
		ts->t_bf_return = bpf_ktime_get_ns();

	bpf_map_delete_elem(&task_addr, &tid);
	return 0;
}

SEC("kprobe/bpf_fault_lock_vma")
int BPF_KPROBE(lv_entry, struct mm_struct *mm, unsigned long address)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 addr;
	struct bpf_overhead_ts *ts;

	if (tgid != target_tgid)
		return 0;

	addr = address & ~(__u64)0xFFF;

	ts = bpf_map_lookup_elem(&kernel_ts, &addr);
	if (ts)
		ts->t_lock_vma = bpf_ktime_get_ns();

	return 0;
}

SEC("kprobe/mfill_atomic_install_pte")
int BPF_KPROBE(ip_entry, pmd_t *dst_pmd, struct vm_area_struct *dst_vma,
	       unsigned long dst_addr)
{
	__u32 tgid = bpf_get_current_pid_tgid() >> 32;
	__u64 addr;
	struct bpf_overhead_ts *ts;

	if (tgid != target_tgid)
		return 0;

	addr = dst_addr & ~(__u64)0xFFF;

	ts = bpf_map_lookup_elem(&kernel_ts, &addr);
	if (ts)
		ts->t_install_pte = bpf_ktime_get_ns();

	return 0;
}

char LICENSE[] SEC("license") = "GPL";
