// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF fault_ops program for page fault benchmark.
 *
 * Fills each faulted page with a repeating byte pattern,
 * mirroring the userfaultfd benchmark workload.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char _license[] SEC("license") = "GPL";

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *buf)
{
	/* Fill the page with 'A' (0x41) to match the userfaultfd benchmark.
	 * Use volatile to prevent clang from converting the loop to memset.
	 */
	volatile unsigned long *p = (volatile unsigned long *)buf;
	unsigned long fill = 0x4141414141414141UL;

	for (int i = 0; i < 4096 / (int)sizeof(unsigned long); i++)
		p[i] = fill;
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops bench_fault_ops = {
	.handle_page_fault = (void *)handle_page_fault,
};
