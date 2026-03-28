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

/*
 * When false, the handler returns immediately without filling the page.
 * The page stays zeroed (from __GFP_ZERO in folio_alloc).  This is the
 * "read fault" / ZEROPAGE equivalent for bpf_fault.
 */
const volatile __u32 fill_page = 1;

SEC("struct_ops/handle_page_fault")
int BPF_PROG(handle_page_fault, struct bpf_fault_ops_ctx *ops_ctx,
	     unsigned char *buf)
{
	volatile unsigned long *p = (volatile unsigned long *)buf;
	unsigned long fill = 0x4141414141414141UL;

	if (!fill_page)
		return 0;

	for (int i = 0; i < 4096 / (int)sizeof(unsigned long); i++)
		p[i] = fill;
	return 0;
}

SEC(".struct_ops.link")
struct fault_ops bench_fault_ops = {
	.handle_page_fault = (void *)handle_page_fault,
};
