/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Shared fault_ops command defines and syscall wrappers for bench_fault.
 *
 * UAPI constants and the BPF_LINK_FAULT_OPS_CMD syscall wrappers used by
 * WP benchmarks, WP tests, and multi-region tests.  Defined here until
 * the constants propagate to system headers.
 */
#ifndef WP_UTIL_H
#define WP_UTIL_H

#include <string.h>
#include <sys/syscall.h>
#include <linux/types.h>
#include <unistd.h>

#ifndef BPF_LINK_FAULT_OPS_CMD
#define BPF_LINK_FAULT_OPS_CMD	38
#endif
#ifndef BPF_FAULT_FLAG_WP
#define BPF_FAULT_FLAG_WP	(1U << 0)
#endif
#ifndef BPF_FAULT_FLAG_INHERIT
#define BPF_FAULT_FLAG_INHERIT	(1U << 1)
#endif
#ifndef BPF_FAULT_WP_ENABLE
#define BPF_FAULT_WP_ENABLE	(1U << 0)
#endif
#ifndef BPF_FAULT_REGISTER
#define BPF_FAULT_REGISTER	(1U << 1)
#endif
#ifndef BPF_FAULT_UNREGISTER
#define BPF_FAULT_UNREGISTER	(1U << 2)
#endif

struct bpf_link_fault_cmd_attr {
	__u32		link_fd;
	__u32		flags;
	__u64		start;
	__u64		len;
} __attribute__((aligned(8)));

static inline int bpf_link_writeprotect(int link_fd, __u64 start, __u64 len,
				 __u32 flags)
{
	struct bpf_link_fault_cmd_attr attr = {
		.link_fd = link_fd,
		.flags = flags,
		.start = start,
		.len = len,
	};

	return syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &attr, sizeof(attr));
}

static inline int bpf_link_fault_register(int link_fd, __u64 start, __u64 len)
{
	struct bpf_link_fault_cmd_attr attr = {
		.link_fd = link_fd,
		.flags = BPF_FAULT_REGISTER,
		.start = start,
		.len = len,
	};

	return syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &attr, sizeof(attr));
}

static inline int bpf_link_fault_unregister(int link_fd, __u64 start,
					    __u64 len)
{
	struct bpf_link_fault_cmd_attr attr = {
		.link_fd = link_fd,
		.flags = BPF_FAULT_UNREGISTER,
		.start = start,
		.len = len,
	};

	return syscall(__NR_bpf, BPF_LINK_FAULT_OPS_CMD, &attr, sizeof(attr));
}

#endif /* WP_UTIL_H */
