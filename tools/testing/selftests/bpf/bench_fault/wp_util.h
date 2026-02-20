/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared write-protect defines and syscall wrapper for bench_fault.
 *
 * UAPI constants and the BPF_LINK_WRITEPROTECT syscall wrapper used by
 * both the WP benchmark and WP tests.  Defined here until the constants
 * propagate to system headers.
 */
#ifndef WP_UTIL_H
#define WP_UTIL_H

#include <string.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include <unistd.h>

#ifndef BPF_LINK_WRITEPROTECT
#define BPF_LINK_WRITEPROTECT	38
#endif
#ifndef BPF_FAULT_FLAG_WP
#define BPF_FAULT_FLAG_WP	(1U << 0)
#endif
#ifndef BPF_FAULT_WP_ENABLE
#define BPF_FAULT_WP_ENABLE	(1U << 0)
#endif

struct bpf_link_wp_attr {
	__u32		link_fd;
	__u32		flags;
	__u64		start;
	__u64		len;
} __attribute__((aligned(8)));

static inline int bpf_link_writeprotect(int link_fd, __u64 start, __u64 len,
				 __u32 flags)
{
	struct bpf_link_wp_attr attr = {
		.link_fd = link_fd,
		.flags = flags,
		.start = start,
		.len = len,
	};

	return syscall(__NR_bpf, BPF_LINK_WRITEPROTECT, &attr, sizeof(attr));
}

#endif /* WP_UTIL_H */
