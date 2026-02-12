// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF-based page fault handling.
 *
 * Allows BPF struct_ops programs to intercept and handle anonymous page
 * faults, similar to userfaultfd but using BPF programs for policy.
 */
#include <linux/bpf_verifier.h>
#include <linux/bpf.h>
#include <linux/btf.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <linux/init.h>
#include <linux/memcontrol.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/pagemap.h>
#include <linux/slab.h>
#include <linux/userfaultfd_k.h>

#include "vma.h"

static struct kmem_cache *bpf_fault_ctx_cachep __ro_after_init;

static const struct btf_type *bpf_fault_ops_ctx_type;

static pmd_t *bpf_fault_alloc_pmd(struct mm_struct *mm, unsigned long address)
{
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;

	pgd = pgd_offset(mm, address);
	p4d = p4d_alloc(mm, pgd, address);
	if (!p4d)
		return NULL;
	pud = pud_alloc(mm, p4d, address);
	if (!pud)
		return NULL;
	return pmd_alloc(mm, pud, address);
}

static void bpf_fault_ctx_get(struct bpf_fault_ctx *ctx)
{
	refcount_inc(&ctx->refcount);
}

static void bpf_fault_ctx_put(struct bpf_fault_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->refcount))
		bpf_fault_ctx_free(ctx);
}

vm_fault_t handle_bpf_fault(struct vm_fault *vmf)
{
	struct bpf_fault_ctx *ctx;
	struct bpf_fault_ops_ctx ops_ctx;
	vm_fault_t ret = VM_FAULT_SIGBUS;
	struct vm_area_struct *vma = vmf->vma;
	struct mm_struct *mm = vma->vm_mm;
	struct fault_ops *ops;
	struct folio *folio = NULL;
	unsigned long address = vmf->address;
	pmd_t *dst_pmd;
	pmd_t dst_pmdval;
	void *kaddr;
	int err;

	/*
	 * We don't do userfault handling for the final child pid update
	 * and when coredumping (faults triggered by get_dump_page()).
	 */
	if (current->flags & (PF_EXITING | PF_DUMPCORE))
		goto out;

	assert_fault_locked(vmf);

	ctx = vma->vm_userfaultfd_ctx.bpf_ctx;
	if (!ctx)
		goto out;

	VM_WARN_ON_ONCE(ctx->mm != mm);

	/*
	 * Check that we can return VM_FAULT_RETRY.
	 */
	if (unlikely(!(vmf->flags & FAULT_FLAG_ALLOW_RETRY))) {
		VM_WARN_ON_ONCE(vmf->flags & FAULT_FLAG_RETRY_NOWAIT);
#ifdef CONFIG_DEBUG_VM
		if (printk_ratelimit()) {
			pr_warn("FAULT_FLAG_ALLOW_RETRY missing %x\n",
				vmf->flags);
			dump_stack();
		}
#endif
		goto out;
	}

	/*
	 * Handle nowait, not much to do other than tell it to retry
	 * and wait.
	 */
	ret = VM_FAULT_RETRY;
	if (vmf->flags & FAULT_FLAG_RETRY_NOWAIT)
		goto out;

	/*
	 * If it's already released don't get it.  This avoids looping
	 * in __get_user_pages if the bpf_fault_ctx is being torn down.
	 *
	 * Use VM_FAULT_RETRY + release_fault_lock() rather than
	 * VM_FAULT_NOPAGE, because faultin_page() does nothing special
	 * on NOPAGE and GUP would spin retrying without releasing the
	 * mmap read lock, causing a possible livelock.
	 */
	if (unlikely(READ_ONCE(ctx->released))) {
		release_fault_lock(vmf);
		goto out;
	}

	/* Take the reference before dropping the mmap_lock */
	bpf_fault_ctx_get(ctx);

	release_fault_lock(vmf);

	/*
	 * Allocate a zeroed folio for the BPF program to populate.
	 * We use folio_alloc rather than vma_alloc_folio because the
	 * mmap_lock has been released and the VMA may be gone.
	 */
	folio = folio_alloc(GFP_HIGHUSER_MOVABLE | __GFP_ZERO, 0);
	if (!folio) {
		ret = VM_FAULT_RETRY;
		goto out_put_ctx;
	}

	/* Map the folio into kernel space for the BPF program */
	kaddr = kmap_local_folio(folio, 0);

	/* Set up BPF context and call the program */
	ops_ctx.vmf = vmf;
	ops_ctx.page = kaddr;

	rcu_read_lock();
	ops = bpf_fault_ops_map(ctx->prog);
	err = ops->handle_page_fault(&ops_ctx);
	rcu_read_unlock();

	kunmap_local(kaddr);

	if (err) {
		ret = VM_FAULT_SIGBUS;
		goto out_put_folio;
	}

	flush_dcache_folio(folio);

	/*
	 * The memory barrier inside __folio_mark_uptodate makes sure that
	 * preceding stores to the page contents become visible before
	 * the set_pte_at() write.
	 */
	__folio_mark_uptodate(folio);

	/*
	 * Re-acquire the mmap read lock to install the PTE.
	 * The VMA must be re-validated since it may have changed.
	 */
	mmap_read_lock(mm);

	vma = vma_lookup(mm, address);
	if (!vma || !bpf_fault_set(vma)) {
		ret = VM_FAULT_SIGBUS;
		goto out_unlock;
	}

	if (mem_cgroup_charge(folio, mm, GFP_KERNEL)) {
		ret = VM_FAULT_OOM;
		goto out_unlock;
	}

	/* Walk page tables to find/allocate the PMD */
	dst_pmd = bpf_fault_alloc_pmd(mm, address);
	if (!dst_pmd) {
		ret = VM_FAULT_OOM;
		goto out_unlock;
	}

	dst_pmdval = pmdp_get_lockless(dst_pmd);
	if (unlikely(pmd_none(dst_pmdval)) &&
	    unlikely(__pte_alloc(mm, dst_pmd))) {
		ret = VM_FAULT_OOM;
		goto out_unlock;
	}

	dst_pmdval = pmdp_get_lockless(dst_pmd);
	if (unlikely(!pmd_present(dst_pmdval) || pmd_trans_huge(dst_pmdval))) {
		/*
		 * PTE was concurrently promoted to THP or is in an
		 * unexpected state.  Return RETRY to let the fault
		 * handler deal with it on the next attempt.
		 */
		ret = VM_FAULT_RETRY;
		goto out_unlock;
	}

	err = mfill_atomic_install_pte(dst_pmd, vma, address,
				       &folio->page, true, 0);

	mmap_read_unlock(mm);

	if (err)
		folio_put(folio);

	/*
	 * Return RETRY whether the install succeeded or not.
	 * On success, the retry will find the PTE present.
	 * On failure, the retry will re-trigger the fault.
	 */
	ret = VM_FAULT_RETRY;
	bpf_fault_ctx_put(ctx);
	return ret;

out_unlock:
	mmap_read_unlock(mm);
out_put_folio:
	folio_put(folio);
out_put_ctx:
	bpf_fault_ctx_put(ctx);
	return ret;

out:
	return ret;
}

struct bpf_fault_ctx *bpf_fault_ctx_alloc(void)
{
	struct bpf_fault_ctx *ctx;

	if (!current->mm)
		return NULL;

	ctx = kmem_cache_alloc(bpf_fault_ctx_cachep, GFP_KERNEL);
	if (!ctx)
		return NULL;

	refcount_set(&ctx->refcount, 1);
	ctx->flags = 0;
	ctx->released = false;
	ctx->prog = NULL;
	ctx->mm = current->mm;
	mmgrab(ctx->mm);

	return ctx;
}

void bpf_fault_ctx_free(struct bpf_fault_ctx *ctx)
{
	if (!ctx)
		return;
	if (ctx->mm)
		mmdrop(ctx->mm);
	kmem_cache_free(bpf_fault_ctx_cachep, ctx);
}

static __always_inline int bpf_fault_validate_range(struct mm_struct *mm,
						    __u64 start, __u64 len)
{
	__u64 task_size = mm->task_size;

	if (start & ~PAGE_MASK)
		return -EINVAL;
	if (len & ~PAGE_MASK)
		return -EINVAL;
	if (!len)
		return -EINVAL;
	if (start < mmap_min_addr)
		return -EINVAL;
	if (start >= task_size)
		return -EINVAL;
	if (len > task_size - start)
		return -EINVAL;
	return 0;
}

/*
 * Register a VMA range for BPF fault handling.  Sets VM_BPF_FAULT on the
 * specified range, similar to how userfaultfd_register sets UFFD flags.
 */
int bpf_fault_register(struct bpf_fault_ctx *ctx, __u64 start, __u64 len)
{
	struct mm_struct *mm = ctx->mm;
	struct vm_area_struct *vma, *prev, *cur;
	int ret;
	vm_flags_t vm_flags = VM_BPF_FAULT;
	vm_flags_t new_flags;
	bool found;
	unsigned long vma_end;
	unsigned long vma_start = start;
	unsigned long end = start + len;
	VMA_ITERATOR(vmi, mm, 0);

	ret = bpf_fault_validate_range(mm, start, len);
	if (ret)
		return ret;

	if (!mmget_not_zero(mm))
		return -ENOMEM;

	mmap_write_lock(mm);
	vma_iter_init(&vmi, mm, vma_start);
	vma = vma_find(&vmi, end);
	if (!vma) {
		ret = -EINVAL;
		goto out_unlock;
	}

	/*
	 * If the first vma contains huge pages, make sure start address
	 * is aligned to huge page size.
	 */
	if (is_vm_hugetlb_page(vma)) {
		unsigned long vma_hpagesize = vma_kernel_pagesize(vma);

		if (vma_start & (vma_hpagesize - 1)) {
			ret = -EINVAL;
			goto out_unlock;
		}
	}

	/* Search for incompatible vmas. */
	found = false;
	cur = vma;
	do {
		cond_resched();

		ret = -EINVAL;
		if (!vma_can_bpf_fault(cur))
			goto out_unlock;

		/*
		 * Enforce that the process has write permission to the
		 * backing file for MAP_SHARED.  If VM_MAYWRITE is set
		 * it also enforces that there is no F_WRITE_SEAL.
		 */
		ret = -EPERM;
		if (unlikely(!(cur->vm_flags & VM_MAYWRITE)))
			goto out_unlock;

		/*
		 * If this vma contains ending address and huge pages,
		 * check alignment.
		 */
		if (is_vm_hugetlb_page(cur) && end <= cur->vm_end &&
		    end > cur->vm_start) {
			unsigned long vma_hpagesize = vma_kernel_pagesize(cur);

			ret = -EINVAL;
			if (end & (vma_hpagesize - 1))
				goto out_unlock;
		}

		/*
		 * Check that this vma isn't already owned by a
		 * different bpf_fault context.
		 */
		ret = -EBUSY;
		if (cur->vm_userfaultfd_ctx.bpf_ctx &&
		    cur->vm_userfaultfd_ctx.bpf_ctx != ctx)
			goto out_unlock;

		found = true;
	} for_each_vma_range(vmi, cur, end);
	BUG_ON(!found);

	vma_iter_set(&vmi, vma_start);
	prev = vma_prev(&vmi);
	if (vma->vm_start < vma_start)
		prev = vma;

	ret = 0;
	for_each_vma_range(vmi, vma, end) {
		cond_resched();

		VM_WARN_ON_ONCE(!vma_can_bpf_fault(vma));
		VM_WARN_ON_ONCE(vma->vm_userfaultfd_ctx.bpf_ctx &&
				vma->vm_userfaultfd_ctx.bpf_ctx != ctx);
		VM_WARN_ON_ONCE(!(vma->vm_flags & VM_MAYWRITE));

		/*
		 * Nothing to do: this vma is already registered into this
		 * bpf_fault and with the right tracking mode.
		 */
		if (vma->vm_userfaultfd_ctx.bpf_ctx == ctx &&
		    (vma->vm_flags & vm_flags) == vm_flags)
			goto skip;

		if (vma->vm_start > vma_start)
			vma_start = vma->vm_start;
		vma_end = min(end, vma->vm_end);

		new_flags = (vma->vm_flags & ~__VM_UFFD_FLAGS) | vm_flags;
		vma = vma_modify_flags_uffd(&vmi, prev, vma,
					    vma_start, vma_end,
					    new_flags,
					    ((struct vm_userfaultfd_ctx){
						.bpf_ctx = ctx }),
					    false);
		if (IS_ERR(vma)) {
			ret = PTR_ERR(vma);
			break;
		}

		/*
		 * In the vma_merge() successful mprotect-like case 8:
		 * the next vma was merged into the current one and
		 * the current one has not been updated yet.
		 */
		vma_start_write(vma);
		vma->vm_userfaultfd_ctx.bpf_ctx = ctx;
		vm_flags_reset(vma, new_flags);

skip:
		prev = vma;
		vma_start = vma->vm_end;
	}

out_unlock:
	mmap_write_unlock(mm);
	mmput(mm);
	return ret;
}

/*
 * BPF verifier operations for fault_ops struct_ops programs.
 */
static const struct bpf_func_proto *
bpf_fault_get_func_proto(enum bpf_func_id func_id,
			 const struct bpf_prog *prog)
{
	switch (func_id) {
	default:
		return bpf_base_func_proto(func_id, prog);
	}
}

static bool bpf_fault_is_valid_access(int off, int size,
				      enum bpf_access_type type,
				      const struct bpf_prog *prog,
				      struct bpf_insn_access_aux *info)
{
	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;

	return btf_ctx_access(off, size, type, prog, info);
}

static int bpf_fault_btf_struct_access(struct bpf_verifier_log *log,
				       const struct bpf_reg_state *reg,
				       int off, int size)
{
	const struct btf_type *t;

	t = btf_type_by_id(reg->btf, reg->btf_id);
	if (t == bpf_fault_ops_ctx_type) {
		if (off + size > sizeof(struct bpf_fault_ops_ctx)) {
			bpf_log(log,
				"out of bounds access at off %d with size %d\n",
				off, size);
			return -EACCES;
		}
		return SCALAR_VALUE;
	}

	return -EACCES;
}

static const struct bpf_verifier_ops bpf_fault_verifier_ops = {
	.get_func_proto = bpf_fault_get_func_proto,
	.is_valid_access = bpf_fault_is_valid_access,
	.btf_struct_access = bpf_fault_btf_struct_access,
};

/*
 * struct_ops callbacks for fault_ops.
 */
static int bpf_fault_ops_init(struct btf *btf)
{
	s32 type_id;

	type_id = btf_find_by_name_kind(btf, "bpf_fault_ops_ctx",
					BTF_KIND_STRUCT);
	if (type_id < 0)
		return -EINVAL;
	bpf_fault_ops_ctx_type = btf_type_by_id(btf, type_id);

	return 0;
}

static int bpf_fault_reg(void *kdata, struct bpf_link *link)
{
	return 0;
}

static void bpf_fault_unreg(void *kdata, struct bpf_link *link)
{
}

static int bpf_fault_init_member(const struct btf_type *t,
				 const struct btf_member *member,
				 void *kdata, const void *udata)
{
	return 0;
}

static int bpf_fault_check_member(const struct btf_type *t,
				  const struct btf_member *member,
				  const struct bpf_prog *prog)
{
	return 0;
}

static int bpf_fault_validate(void *kdata)
{
	return 0;
}

static int __bpf_fault_handle_page_fault(struct bpf_fault_ops_ctx *ctx)
{
	return 0;
}

static struct fault_ops __bpf_fault_ops = {
	.handle_page_fault = __bpf_fault_handle_page_fault,
};

static struct bpf_struct_ops bpf_fault_struct_ops = {
	.verifier_ops = &bpf_fault_verifier_ops,
	.init = bpf_fault_ops_init,
	.reg = bpf_fault_reg,
	.unreg = bpf_fault_unreg,
	.init_member = bpf_fault_init_member,
	.check_member = bpf_fault_check_member,
	.validate = bpf_fault_validate,
	.cfi_stubs = &__bpf_fault_ops,
	.name = "fault_ops",
};

static int __init bpf_fault_init(void)
{
	int ret;

	bpf_fault_ctx_cachep = kmem_cache_create(
		"bpf_fault_ctx_cachep", sizeof(struct bpf_fault_ctx), 0,
		SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);

	ret = register_bpf_struct_ops(&bpf_fault_struct_ops, fault_ops);
	if (ret) {
		pr_err("bpf_fault: failed to register struct_ops: %d\n", ret);
		return ret;
	}

	return 0;
}
__initcall(bpf_fault_init);
