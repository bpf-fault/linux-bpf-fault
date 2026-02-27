// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF fault_ops program for write-protect fault tests.
 *
 * Provides a handle_wp_fault callback that allows every write fault
 * and counts invocations.  Also includes a handle_page_fault that
 * fills pages with 'A' (used to verify missing+WP combinations or
 * to confirm missing faults are NOT intercepted in WP-only mode).
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

/* Counter: incremented on each WP fault handled by BPF */
volatile __u64 wp_fault_count = 0;

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *buf)
{
	volatile unsigned long *p = (volatile unsigned long *)buf;
	unsigned long fill = 0x4141414141414141UL;

	for (int i = 0; i < 4096 / (int)sizeof(unsigned long); i++)
		p[i] = fill;
	return 0;
}

SEC("struct_ops/handle_wp_fault")
int BPF_PROG(handle_wp_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *buf)
{
	__sync_fetch_and_add(&wp_fault_count, 1);
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops wp_fault_ops = {
	.handle_page_fault = (void *)handle_page_fault,
	.handle_wp_fault = (void *)handle_wp_fault,
};
