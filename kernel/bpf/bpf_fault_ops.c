// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF fault ops link implementation.
 *
 * Provides the BPF link type for fault_ops struct_ops maps,
 * including link lifecycle management for BPF-based page fault handling.
 */
#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/mm.h>
#include <linux/mutex.h>
#include <linux/userfaultfd_k.h>

#include "bpf_struct_ops.h"

static DEFINE_MUTEX(fault_update_mutex);

struct bpf_fault_ops_link {
	struct bpf_link link;
	struct bpf_map __rcu *map;
	struct bpf_fault_ctx *ctx;
};

struct fault_ops *bpf_fault_ops_map(struct bpf_fault_ops_link *link)
{
	struct bpf_struct_ops_map *st_map;

	st_map = (struct bpf_struct_ops_map *)rcu_dereference(link->map);
	return (struct fault_ops *)st_map->kvalue.data;
}

static void bpf_fault_ops_link_dealloc(struct bpf_link *link)
{
	struct bpf_fault_ops_link *st_link;
	struct bpf_struct_ops_map *st_map;

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	st_map = (struct bpf_struct_ops_map *)
		rcu_dereference_protected(st_link->map, true);
	if (st_map) {
		/*
		 * st_link->map can be NULL if
		 * bpf_fault_ops_link_create() fails to register.
		 */
		st_map->st_ops_desc->st_ops->unreg(&st_map->kvalue.data,
						    &st_link->link);
		bpf_map_put(&st_map->map);
	}

	bpf_fault_release_all(st_link->ctx);
	bpf_fault_ctx_put(st_link->ctx);
	kfree(st_link);
}

static void bpf_fault_ops_link_show_fdinfo(const struct bpf_link *link,
					   struct seq_file *seq)
{
	struct bpf_fault_ops_link *st_link;
	struct bpf_map *map;

	st_link = container_of(link, struct bpf_fault_ops_link, link);

	rcu_read_lock();
	map = rcu_dereference(st_link->map);
	if (map)
		seq_printf(seq, "map_id:\t%d\n", map->id);
	rcu_read_unlock();
}

static int bpf_fault_ops_link_fill_link_info(const struct bpf_link *link,
					     struct bpf_link_info *info)
{
	struct bpf_fault_ops_link *st_link;
	struct bpf_map *map;

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	rcu_read_lock();
	map = rcu_dereference(st_link->map);
	if (map)
		info->fault_ops.map_id = map->id;
	rcu_read_unlock();
	return 0;
}

static int bpf_fault_ops_link_update(struct bpf_link *link,
				     struct bpf_map *new_map,
				     struct bpf_map *expected_old_map)
{
	struct bpf_struct_ops_map *st_map, *old_st_map;
	struct bpf_map *old_map;
	struct bpf_fault_ops_link *st_link;
	int err;

	st_link = container_of(link, struct bpf_fault_ops_link, link);
	st_map = container_of(new_map, struct bpf_struct_ops_map, map);

	if (!bpf_struct_ops_valid_to_reg(new_map))
		return -EINVAL;

	if (!st_map->st_ops_desc->st_ops->update)
		return -EOPNOTSUPP;

	mutex_lock(&fault_update_mutex);

	old_map = rcu_dereference_protected(st_link->map,
					    lockdep_is_held(&fault_update_mutex));
	if (!old_map) {
		err = -ENOLINK;
		goto err_out;
	}
	if (expected_old_map && old_map != expected_old_map) {
		err = -EPERM;
		goto err_out;
	}

	old_st_map = container_of(old_map, struct bpf_struct_ops_map, map);
	/* The new and old struct_ops must be the same type. */
	if (st_map->st_ops_desc != old_st_map->st_ops_desc) {
		err = -EINVAL;
		goto err_out;
	}

	err = st_map->st_ops_desc->st_ops->update(st_map->kvalue.data,
						   old_st_map->kvalue.data,
						   link);
	if (err)
		goto err_out;

	bpf_map_inc(new_map);
	rcu_assign_pointer(st_link->map, new_map);
	bpf_map_put(old_map);

err_out:
	mutex_unlock(&fault_update_mutex);
	return err;
}

static const struct bpf_link_ops bpf_fault_ops_link_lops = {
	.dealloc = bpf_fault_ops_link_dealloc,
	.show_fdinfo = bpf_fault_ops_link_show_fdinfo,
	.fill_link_info = bpf_fault_ops_link_fill_link_info,
	.update_map = bpf_fault_ops_link_update,
};

int bpf_fault_ops_link_create(union bpf_attr *attr)
{
	struct bpf_fault_ops_link *link = NULL;
	struct bpf_link_primer link_primer;
	struct bpf_struct_ops_map *st_map;
	struct bpf_map *map;
	int err;

	map = bpf_map_get(attr->link_create.map_fd);
	if (IS_ERR(map))
		return PTR_ERR(map);

	st_map = (struct bpf_struct_ops_map *)map;

	if (!bpf_struct_ops_valid_to_reg(map)) {
		err = -EINVAL;
		goto err_out;
	}

	link = kzalloc(sizeof(*link), GFP_USER);
	if (!link) {
		err = -ENOMEM;
		goto err_out;
	}
	bpf_link_init(&link->link, BPF_LINK_TYPE_FAULT_OPS,
		      &bpf_fault_ops_link_lops, NULL,
		      attr->link_create.attach_type);

	err = bpf_link_prime(&link->link, &link_primer);
	if (err)
		goto err_out;

	link->ctx = bpf_fault_ctx_alloc();
	if (!link->ctx) {
		err = -ENOMEM;
		bpf_link_cleanup(&link_primer);
		link = NULL;
		goto err_out;
	}

	/*
	 * Hold the mutex so the subsystem cannot do link->ops->detach()
	 * before the link is fully initialized.
	 */
	mutex_lock(&fault_update_mutex);
	err = st_map->st_ops_desc->st_ops->reg(st_map->kvalue.data,
						&link->link);
	if (err) {
		mutex_unlock(&fault_update_mutex);
		bpf_fault_ctx_free(link->ctx);
		bpf_link_cleanup(&link_primer);
		link = NULL;
		goto err_out;
	}
	mutex_unlock(&fault_update_mutex);

	link->ctx->prog = link;

	err = bpf_fault_register(link->ctx,
				 attr->link_create.fault.start,
				 attr->link_create.fault.len);
	if (err) {
		/* Undo reg() — dealloc won't call unreg since map isn't set. */
		st_map->st_ops_desc->st_ops->unreg(st_map->kvalue.data,
						    &link->link);
		bpf_link_cleanup(&link_primer);
		link = NULL;
		goto err_out;
	}

	RCU_INIT_POINTER(link->map, map);
	return bpf_link_settle(&link_primer);

err_out:
	bpf_map_put(map);
	kfree(link);
	return err;
}
