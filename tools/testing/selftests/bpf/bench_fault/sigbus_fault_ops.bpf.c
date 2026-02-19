// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF fault_ops program that rejects missing faults with SIGBUS.
 *
 * Returns -1 from handle_page_fault, which causes the kernel
 * to deliver SIGBUS to the faulting process instead of installing
 * a page.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

__u64 fault_count;
__u64 wp_fault_count;

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *buf)
{
	__sync_fetch_and_add(&fault_count, 1);
	return -1;
}

SEC("struct_ops/handle_wp_fault")
int BPF_PROG(handle_wp_fault, struct bpf_fault_ops_ctx *ops_ctx)
{
	__sync_fetch_and_add(&wp_fault_count, 1);
	return -1;
}

SEC(".struct_ops.link")
struct fault_ops sigbus_fault_ops = {
	.handle_page_fault = (void *)handle_page_fault,
	.handle_wp_fault = (void *)handle_wp_fault,
};
