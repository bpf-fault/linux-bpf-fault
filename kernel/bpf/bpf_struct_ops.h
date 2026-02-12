/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef __BPF_STRUCT_OPS_H_
#define __BPF_STRUCT_OPS_H_

#include <linux/bpf.h>

struct bpf_struct_ops_value {
	struct bpf_struct_ops_common_value common;
	char data[] ____cacheline_aligned_in_smp;
};

#define MAX_TRAMP_IMAGE_PAGES 8

struct bpf_struct_ops_map {
	struct bpf_map map;
	const struct bpf_struct_ops_desc *st_ops_desc;
	/* protect map_update */
	struct mutex lock;
	/* link has all the bpf_links that is populated
	 * to the func ptr of the kernel's struct
	 * (in kvalue.data).
	 */
	struct bpf_link **links;
	/* ksyms for bpf trampolines */
	struct bpf_ksym **ksyms;
	u32 funcs_cnt;
	u32 image_pages_cnt;
	/* image_pages is an array of pages that has all the trampolines
	 * that stores the func args before calling the bpf_prog.
	 */
	void *image_pages[MAX_TRAMP_IMAGE_PAGES];
	/* The owner moduler's btf. */
	struct btf *btf;
	/* uvalue->data stores the kernel struct
	 * (e.g. tcp_congestion_ops) that is more useful
	 * to userspace than the kvalue.  For example,
	 * the bpf_prog's id is stored instead of the kernel
	 * address of a func ptr.
	 */
	struct bpf_struct_ops_value *uvalue;
	/* kvalue.data stores the actual kernel's struct
	 * (e.g. tcp_congestion_ops) that will be
	 * registered to the kernel subsystem.
	 */
	struct bpf_struct_ops_value kvalue;
};

bool bpf_struct_ops_valid_to_reg(struct bpf_map *map);

#endif /* __BPF_STRUCT_OPS_H_ */
