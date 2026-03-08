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
#include <linux/btf_ids.h>
#include <linux/highmem.h>
#include <linux/hugetlb.h>
#include <asm-generic/tlb.h>
#include <linux/init.h>
#include <linux/memcontrol.h>
#include <linux/mmap_lock.h>
#include <linux/mm.h>
#include <linux/mm_types.h>
#include <linux/pagemap.h>
#include <linux/rmap.h>
#include <linux/sched/signal.h>
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

/*
 * Lock a VMA for PTE installation.  Mirrors userfaultfd's uffd_lock_vma():
 * try the per-VMA lock first for scalability, falling back to mmap_read_lock
 * when anon_vma needs to be allocated or per-VMA locking fails.
 *
 * On success, returns the VMA with appropriate lock held.
 * Caller must use bpf_fault_unlock_vma() to release.
 */
#ifdef CONFIG_PER_VMA_LOCK

static struct vm_area_struct *bpf_fault_lock_vma(struct mm_struct *mm,
						 unsigned long address)
{
	struct vm_area_struct *vma;

	vma = lock_vma_under_rcu(mm, address);
	if (vma) {
		/*
		 * We need anon_vma for folio_add_new_anon_rmap().  If it
		 * is not yet allocated, fall back to mmap_read_lock so
		 * anon_vma_prepare() can safely allocate it.
		 */
		if (!(vma->vm_flags & VM_SHARED) && unlikely(!vma->anon_vma))
			vma_end_read(vma);
		else
			return vma;
	}

	mmap_read_lock(mm);
	vma = vma_lookup(mm, address);
	if (!vma) {
		mmap_read_unlock(mm);
		return ERR_PTR(-ENOENT);
	}

	if (!(vma->vm_flags & VM_SHARED) && unlikely(anon_vma_prepare(vma))) {
		mmap_read_unlock(mm);
		return ERR_PTR(-ENOMEM);
	}

	if (!vma_start_read_locked(vma)) {
		mmap_read_unlock(mm);
		return ERR_PTR(-EAGAIN);
	}
	mmap_read_unlock(mm);
	return vma;
}

static void bpf_fault_unlock_vma(struct vm_area_struct *vma)
{
	vma_end_read(vma);
}

#else /* !CONFIG_PER_VMA_LOCK */

static struct vm_area_struct *bpf_fault_lock_vma(struct mm_struct *mm,
						 unsigned long address)
{
	struct vm_area_struct *vma;

	mmap_read_lock(mm);
	vma = vma_lookup(mm, address);
	if (!vma) {
		mmap_read_unlock(mm);
		return ERR_PTR(-ENOENT);
	}

	if (!(vma->vm_flags & VM_SHARED) && unlikely(anon_vma_prepare(vma))) {
		mmap_read_unlock(mm);
		return ERR_PTR(-ENOMEM);
	}

	return vma;
}

static void bpf_fault_unlock_vma(struct vm_area_struct *vma)
{
	mmap_read_unlock(vma->vm_mm);
}

#endif /* CONFIG_PER_VMA_LOCK */

static void bpf_fault_ctx_get(struct bpf_fault_ctx *ctx)
{
	refcount_inc(&ctx->refcount);
}

void bpf_fault_ctx_put(struct bpf_fault_ctx *ctx)
{
	if (refcount_dec_and_test(&ctx->refcount))
		bpf_fault_ctx_free(ctx);
}

/*
 * Handle a write-protection fault on a bpf_fault WP-registered VMA.
 *
 * Called from do_wp_page() with the PTE lock already released.  The BPF
 * program decides whether to allow the write (return 0) or deny it
 * (return non-zero -> SIGBUS).
 *
 * On allow: re-acquire VMA lock, re-walk page tables, clear the uffd-wp
 * bit on the PTE, and return VM_FAULT_RETRY so the fault retries and
 * finds the PTE writable.
 */
vm_fault_t handle_bpf_fault_wp(struct vm_fault *vmf)
{
	struct bpf_fault_ctx *ctx;
	struct bpf_fault_ops_ctx ops_ctx;
	vm_fault_t ret = VM_FAULT_SIGBUS;
	struct vm_area_struct *vma = vmf->vma;
	struct mm_struct *mm = vma->vm_mm;
	unsigned long address = vmf->address;
	struct folio *folio = NULL;
	size_t folio_off = 0;
	struct fault_ops *ops;
	void *kaddr;
	int err;

	if (current->flags & (PF_EXITING | PF_DUMPCORE))
		goto out;

	ctx = vma->vm_userfaultfd_ctx.bpf_ctx;
	if (!ctx)
		goto out;

	if (unlikely(!(vmf->flags & FAULT_FLAG_ALLOW_RETRY)))
		goto out;

	ret = VM_FAULT_RETRY;
	if (vmf->flags & FAULT_FLAG_RETRY_NOWAIT)
		goto out;

	if (unlikely(READ_ONCE(ctx->released))) {
		release_fault_lock(vmf);
		goto out;
	}

	/* Take the reference before dropping the fault lock */
	bpf_fault_ctx_get(ctx);

	release_fault_lock(vmf);

	/*
	 * Look up the existing page so the BPF program can read its
	 * contents.  The page is present (this is a WP fault), so walk
	 * the page tables under VMA lock to get a folio reference.
	 */
	vma = bpf_fault_lock_vma(mm, address);
	if (IS_ERR(vma)) {
		ret = VM_FAULT_RETRY;
		goto out_put_ctx;
	}

	if (bpf_fault_wp(vma)) {
		pmd_t *pmd;
		pte_t *ptep, pte;
		spinlock_t *ptl;
		struct page *page;

		pmd = bpf_fault_alloc_pmd(mm, address);
		if (!pmd)
			goto out_no_page;

		ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
		if (!ptep)
			goto out_no_page;

		pte = ptep_get(ptep);
		if (pte_present(pte)) {
			page = vm_normal_page(vma, address, pte);
			if (page) {
				folio = page_folio(page);
				folio_off = folio_page_idx(folio, page) *
					    PAGE_SIZE;
				folio_get(folio);
			}
		}
		pte_unmap_unlock(ptep, ptl);
	}

out_no_page:
	bpf_fault_unlock_vma(vma);

	if (folio)
		kaddr = kmap_local_folio(folio, folio_off);
	else
		kaddr = NULL;

	/* Set up BPF context and call the WP fault handler */
	ops_ctx.address = vmf->address;
	ops_ctx.real_address = vmf->real_address;
	ops_ctx.fault_type = BPF_FAULT_WP;

	rcu_read_lock();
	ops = bpf_fault_ops_map(ctx->prog);
	if (ops->handle_wp_fault)
		err = ops->handle_wp_fault(&ops_ctx, kaddr);
	else
		err = -ENOSYS;
	rcu_read_unlock();

	if (kaddr)
		kunmap_local(kaddr);
	if (folio)
		folio_put(folio);

	if (err) {
		/*
		 * The fault lock was already released above, so we
		 * cannot return VM_FAULT_SIGBUS (the caller would
		 * double-release the VMA lock).  Deliver SIGBUS
		 * directly and return RETRY so the caller skips its
		 * own unlock and the signal is handled on return to
		 * userspace.
		 */
		force_sig_fault(SIGBUS, BUS_ADRERR,
				(void __user *)address);
		ret = VM_FAULT_RETRY;
		goto out_put_ctx;
	}

	/*
	 * BPF program allowed the write.  Re-acquire a lock and clear
	 * the uffd-wp bit on the PTE to resolve the write protection.
	 */
	vma = bpf_fault_lock_vma(mm, address);
	if (IS_ERR(vma)) {
		ret = VM_FAULT_RETRY;
		goto out_put_ctx;
	}

	if (bpf_fault_wp(vma)) {
		pmd_t *pmd;
		pte_t *ptep, pte;
		spinlock_t *ptl;

		pmd = bpf_fault_alloc_pmd(mm, address);
		if (!pmd)
			goto out_unlock;

		ptep = pte_offset_map_lock(mm, pmd, address, &ptl);
		if (!ptep)
			goto out_unlock;

		pte = ptep_get(ptep);
		if (pte_present(pte) && pte_uffd_wp(pte)) {
			pte = pte_clear_uffd_wp(pte);
			set_pte_at(mm, address, ptep, pte);
		}
		pte_unmap_unlock(ptep, ptl);
	}

out_unlock:
	bpf_fault_unlock_vma(vma);
	ret = VM_FAULT_RETRY;

out_put_ctx:
	bpf_fault_ctx_put(ctx);
	return ret;

out:
	return ret;
}

vm_fault_t handle_bpf_fault(struct vm_fault *vmf, bool can_complete)
{
	struct bpf_fault_ctx *ctx;
	struct bpf_fault_ops_ctx ops_ctx;
	vm_fault_t ret = VM_FAULT_SIGBUS;
	struct vm_area_struct *vma = vmf->vma;
	struct mm_struct *mm = vma->vm_mm;
	struct address_space *mapping = NULL;
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

	/*
	 * Save the mapping before dropping the lock.  After
	 * release_fault_lock() the VMA may be torn down by munmap(),
	 * so we cannot touch vma->vm_ops or vma->vm_file afterwards.
	 * vm_file holds a reference to the inode that keeps the
	 * address_space alive independently of the VMA.
	 */
	if (vma->vm_ops && vma->vm_file)
		mapping = vma->vm_file->f_mapping;

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

	/*
	 * For shmem/file-backed VMAs, pre-populate the page with existing
	 * page cache contents so the BPF program sees the actual data.
	 * We use the mapping pointer saved before release_fault_lock()
	 * since the VMA may have been torn down by now.
	 */
	if (mapping) {
		struct folio *src;

		src = filemap_lock_folio(mapping, vmf->pgoff);
		if (!IS_ERR(src)) {
			size_t off = offset_in_folio(src, vmf->pgoff << PAGE_SHIFT);

			memcpy_from_folio(kaddr, src, off, PAGE_SIZE);
			folio_unlock(src);
			folio_put(src);
		}
	}

	/* Set up BPF context and call the program */
	ops_ctx.address = vmf->address;
	ops_ctx.real_address = vmf->real_address;
	ops_ctx.fault_type = BPF_FAULT_MISSING;

	rcu_read_lock();
	ops = bpf_fault_ops_map(ctx->prog);
	err = ops->handle_page_fault(&ops_ctx, kaddr);
	rcu_read_unlock();

	kunmap_local(kaddr);

	if (err) {
		/*
		 * The fault lock was already released above, so we
		 * cannot return VM_FAULT_SIGBUS (the caller would
		 * double-release the VMA lock).  Deliver SIGBUS
		 * directly and return RETRY so the caller skips its
		 * own unlock and the signal is handled on return to
		 * userspace.
		 */
		force_sig_fault(SIGBUS, BUS_ADRERR,
				(void __user *)address);
		ret = VM_FAULT_RETRY;
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
	 * Re-acquire a lock to install the PTE.  bpf_fault_lock_vma()
	 * uses per-VMA locking when available for scalability, falling
	 * back to mmap_read_lock.  It also ensures anon_vma is allocated
	 * (required by folio_add_new_anon_rmap's BUG_ON(!anon_vma)).
	 */
	vma = bpf_fault_lock_vma(mm, address);
	if (IS_ERR(vma)) {
		ret = VM_FAULT_RETRY;
		goto out_put_folio;
	}

	if (!bpf_fault_missing(vma))
		goto out_unlock;

	if (mem_cgroup_charge(folio, mm, GFP_KERNEL))
		goto out_unlock;

	/* Walk page tables to find/allocate the PMD */
	dst_pmd = bpf_fault_alloc_pmd(mm, address);
	if (!dst_pmd)
		goto out_unlock;

	dst_pmdval = pmdp_get_lockless(dst_pmd);
	if (unlikely(pmd_none(dst_pmdval)) &&
	    unlikely(__pte_alloc(mm, dst_pmd)))
		goto out_unlock;

	dst_pmdval = pmdp_get_lockless(dst_pmd);
	if (unlikely(!pmd_present(dst_pmdval) || pmd_trans_huge(dst_pmdval)))
		goto out_unlock;

	if (unlikely(pmd_bad(dst_pmdval)))
		goto out_unlock;

	err = mfill_atomic_install_pte(dst_pmd, vma, address,
				       &folio->page, true,
				       bpf_fault_wp(vma) ? MFILL_ATOMIC_WP : 0);

	bpf_fault_unlock_vma(vma);

	if (err) {
		folio_put(folio);
		ret = VM_FAULT_RETRY;
	} else if (can_complete) {
		/*
		 * Direct callers (anon page faults, file-backed faults
		 * from do_fault): PTE installed and VMA lock released.
		 * Return COMPLETED so the arch fault code skips the
		 * retry, avoiding a redundant VMA lookup + page table
		 * walk just to find the PTE present.
		 *
		 * Callers nested inside filesystem fault handlers
		 * (e.g. shmem_fault → __do_fault) must use RETRY
		 * because the intermediate callers don't handle
		 * COMPLETED and would try to process a folio that
		 * doesn't exist.
		 */
		ret = VM_FAULT_COMPLETED;
	} else {
		ret = VM_FAULT_RETRY;
	}
	bpf_fault_ctx_put(ctx);
	return ret;

out_unlock:
	bpf_fault_unlock_vma(vma);
	/*
	 * The original fault lock was released by release_fault_lock()
	 * above.  We must return RETRY so the caller does not try to
	 * release it a second time.  Transient errors (OOM, VMA race)
	 * resolve naturally on the retry through the normal fault path.
	 */
	ret = VM_FAULT_RETRY;
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
	ctx->inherited = 0;
	ctx->parent_link_id = 0;
	ctx->prog = NULL;
	ctx->mm = current->mm;
	mmgrab(ctx->mm);

	return ctx;
}

/*
 * Allocate a bpf_fault_ctx for a fork child, sharing the parent's
 * struct_ops map.  The child gets its own lightweight link that
 * holds a reference on the map but has no fd or bpf_link lifecycle.
 */
struct bpf_fault_ctx *bpf_fault_ctx_alloc_for_mm(struct mm_struct *mm,
						  struct bpf_fault_ctx *parent)
{
	struct bpf_fault_ops_link *child_link;
	struct bpf_fault_ctx *ctx;

	ctx = kmem_cache_alloc(bpf_fault_ctx_cachep, GFP_KERNEL);
	if (!ctx)
		return NULL;

	child_link = bpf_fault_ops_link_alloc_inherited(parent->prog);
	if (!child_link) {
		kmem_cache_free(bpf_fault_ctx_cachep, ctx);
		return NULL;
	}

	refcount_set(&ctx->refcount, 1);
	ctx->flags = parent->flags;
	ctx->released = false;
	ctx->inherited = 1;
	ctx->parent_link_id = 0;
	ctx->mm = mm;
	mmgrab(mm);
	ctx->prog = child_link;

	return ctx;
}

/*
 * Find an inherited bpf_fault_ctx in the given mm that was forked from
 * the parent link with the specified ID.  Returns the ctx with the
 * mmap read lock released, or NULL if not found.
 */
struct bpf_fault_ctx *bpf_fault_find_inherited_ctx(struct mm_struct *mm,
						   u32 parent_link_id)
{
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);

	mmap_read_lock(mm);
	for_each_vma(vmi, vma) {
		struct bpf_fault_ctx *ctx = vma->vm_userfaultfd_ctx.bpf_ctx;

		if (ctx && ctx->inherited &&
		    ctx->parent_link_id == parent_link_id) {
			mmap_read_unlock(mm);
			return ctx;
		}
	}
	mmap_read_unlock(mm);
	return NULL;
}

void bpf_fault_ctx_free(struct bpf_fault_ctx *ctx)
{
	if (!ctx)
		return;

	if (ctx->inherited)
		bpf_fault_ops_link_free_inherited(ctx->prog);

	if (ctx->mm)
		mmdrop(ctx->mm);
	kmem_cache_free(bpf_fault_ctx_cachep, ctx);
}

/*
 * Clean up inherited bpf_fault contexts when an mm is torn down.
 * Non-inherited contexts are cleaned up by the link fd close path,
 * but inherited contexts have no fd and must be cleaned up here.
 */
void bpf_fault_exit_mm(struct mm_struct *mm)
{
	struct vm_area_struct *vma;
	VMA_ITERATOR(vmi, mm, 0);

	/*
	 * Walk all VMAs and clean up inherited bpf_fault contexts.
	 * Multiple VMAs may share the same ctx — bpf_fault_release_all()
	 * sets ctx->released as its first action, which serves as a
	 * natural deduplication marker for subsequent VMAs.
	 */
	for_each_vma(vmi, vma) {
		struct bpf_fault_ctx *ctx = vma->vm_userfaultfd_ctx.bpf_ctx;

		if (!ctx || !ctx->inherited || ctx->released)
			continue;

		bpf_fault_release_all(ctx);
		bpf_fault_ctx_put(ctx);
	}
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
 *
 * Internal helper: assumes ctx->flags is already set by the caller.
 */
static int __bpf_fault_register_range(struct bpf_fault_ctx *ctx,
				      __u64 start, __u64 len)
{
	struct mm_struct *mm = ctx->mm;
	struct vm_area_struct *vma, *prev, *cur;
	int ret;
	vm_flags_t vm_flags = 0;
	vm_flags_t new_flags;
	bool found;
	unsigned long vma_end;
	unsigned long vma_start = start;
	unsigned long end = start + len;

	if (ctx->flags & BPF_FAULT_FLAG_WP)
		vm_flags |= VM_BPF_FAULT_WP;
	else
		vm_flags |= VM_BPF_FAULT;

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

		/* Shared file-backed VMAs not yet supported (needs file rmap). */
		if (!vma_is_anonymous(cur) && (cur->vm_flags & VM_SHARED))
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

		new_flags = (vma->vm_flags & ~(__VM_UFFD_FLAGS |
			     VM_BPF_FAULT | VM_BPF_FAULT_WP)) | vm_flags;
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

int bpf_fault_register(struct bpf_fault_ctx *ctx, __u64 start, __u64 len,
		       __u32 flags)
{
	ctx->flags = flags;
	return __bpf_fault_register_range(ctx, start, len);
}

int bpf_fault_add_region(struct bpf_fault_ctx *ctx, __u64 start, __u64 len)
{
	return __bpf_fault_register_range(ctx, start, len);
}

static struct vm_area_struct *bpf_fault_clear_vma(struct vma_iterator *vmi,
						  struct vm_area_struct *prev,
						  struct vm_area_struct *vma,
						  unsigned long start,
						  unsigned long end);

/*
 * Unregister a VMA range from BPF fault handling.  Clears VM_BPF_FAULT
 * and VM_BPF_FAULT_WP from the specified range.
 */
int bpf_fault_unregister(struct bpf_fault_ctx *ctx, __u64 start, __u64 len)
{
	struct mm_struct *mm = ctx->mm;
	struct vm_area_struct *vma, *prev, *cur;
	int ret;
	unsigned long vma_start = start;
	unsigned long end = start + len;
	bool found;
	VMA_ITERATOR(vmi, mm, 0);

	ret = bpf_fault_validate_range(mm, start, len);
	if (ret)
		return ret;

	if (!mmget_not_zero(mm))
		return -ENOMEM;

	mmap_write_lock(mm);

	/*
	 * Phase 1: validate all VMAs in range belong to this ctx
	 * (or are unregistered).
	 */
	vma_iter_init(&vmi, mm, vma_start);
	vma = vma_find(&vmi, end);
	if (!vma) {
		ret = -EINVAL;
		goto out_unlock;
	}

	found = false;
	cur = vma;
	do {
		cond_resched();

		if (cur->vm_userfaultfd_ctx.bpf_ctx &&
		    cur->vm_userfaultfd_ctx.bpf_ctx != ctx) {
			ret = -EINVAL;
			goto out_unlock;
		}

		found = true;
	} for_each_vma_range(vmi, cur, end);
	BUG_ON(!found);

	/*
	 * Phase 2: clear bpf_fault flags from each registered VMA
	 * in range.
	 */
	vma_iter_set(&vmi, vma_start);
	prev = vma_prev(&vmi);
	if (vma->vm_start < vma_start)
		prev = vma;

	ret = 0;
	for_each_vma_range(vmi, vma, end) {
		cond_resched();

		if (!bpf_fault_set(vma)) {
			prev = vma;
			continue;
		}

		if (vma->vm_userfaultfd_ctx.bpf_ctx != ctx) {
			prev = vma;
			continue;
		}

		if (vma->vm_start > vma_start)
			vma_start = vma->vm_start;

		vma = bpf_fault_clear_vma(&vmi, prev, vma,
					  vma_start, min(end, vma->vm_end));
		if (IS_ERR(vma)) {
			ret = PTR_ERR(vma);
			break;
		}

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
	const char *fname = prog->aux->attach_func_name;
	bool is_wp = fname && !strcmp(fname, "handle_wp_fault");

	if (off < 0 || off >= sizeof(__u64) * MAX_BPF_FUNC_ARGS)
		return false;
	if (type != BPF_READ)
		return false;
	if (off % size != 0)
		return false;

	/*
	 * For handle_page_fault and handle_wp_fault: arg1 is the page
	 * pointer (PTR_TO_MEM, PAGE_SIZE bounds).  For handle_page_fault
	 * the page is writable; for handle_wp_fault it is read-only
	 * (may also be NULL if the page table walk failed).
	 */
	if (off == sizeof(__u64)) {
		info->reg_type = is_wp ?
			PTR_TO_MEM | PTR_MAYBE_NULL | MEM_RDONLY :
			PTR_TO_MEM;
		info->mem_size = PAGE_SIZE;
		return true;
	}

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

static struct vm_area_struct *bpf_fault_clear_vma(struct vma_iterator *vmi,
						  struct vm_area_struct *prev,
						  struct vm_area_struct *vma,
						  unsigned long start,
						  unsigned long end)
{
	struct vm_area_struct *ret;
	bool give_up_on_oom = false;

	/*
	 * If WP was active, resolve all write-protection markers before
	 * clearing the VMA flags.  This is analogous to userfaultfd_clear_vma
	 * calling uffd_wp_range(vma, ..., false).
	 */
	if (vma->vm_flags & VM_BPF_FAULT_WP)
		uffd_wp_range(vma, start, end - start, false);

	if (start == vma->vm_start && end == vma->vm_end)
		give_up_on_oom = true;

	ret = vma_modify_flags_uffd(vmi, prev, vma, start, end,
				    vma->vm_flags & ~(VM_BPF_FAULT | VM_BPF_FAULT_WP),
				    NULL_VM_UFFD_CTX, give_up_on_oom);

	/*
	 * In the vma_merge() successful mprotect-like case 8:
	 * the next vma was merged into the current one and
	 * the current one has not been updated yet.
	 */
	if (!IS_ERR(ret)) {
		vma_start_write(ret);
		ret->vm_userfaultfd_ctx.bpf_ctx = NULL;
		vm_flags_reset(ret, ret->vm_flags & ~(VM_BPF_FAULT | VM_BPF_FAULT_WP));
	}

	return ret;
}

void bpf_fault_release_all(struct bpf_fault_ctx *ctx)
{
	struct mm_struct *mm;

	if (!ctx)
		return;

	mm = ctx->mm;
	struct vm_area_struct *vma, *prev;
	VMA_ITERATOR(vmi, mm, 0);

	WRITE_ONCE(ctx->released, true);

	if (!mmget_not_zero(mm))
		return;

	/*
	 * Flush page faults out of all CPUs. All page faults must be
	 * retried without returning VM_FAULT_SIGBUS if bpf_fault_ctx_get()
	 * succeeds but vma->vm_userfaultfd_ctx changes while
	 * handle_bpf_fault released the mmap_lock. So it's critical that
	 * released is set to true (above), before taking the mmap_lock
	 * for writing.
	 */
	mmap_write_lock(mm);
	prev = NULL;
	for_each_vma(vmi, vma) {
		cond_resched();
		if (vma->vm_userfaultfd_ctx.bpf_ctx != ctx) {
			prev = vma;
			continue;
		}

		vma = bpf_fault_clear_vma(&vmi, prev, vma,
					  vma->vm_start, vma->vm_end);
		prev = vma;
	}
	mmap_write_unlock(mm);
	mmput(mm);
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

static int __bpf_fault_handle_page_fault(struct bpf_fault_ops_ctx *ctx,
					 unsigned char *page)
{
	return 0;
}

static int __bpf_fault_handle_wp_fault(struct bpf_fault_ops_ctx *ctx,
				       unsigned char *page)
{
	return 0;
}

static struct fault_ops __bpf_fault_ops = {
	.handle_page_fault = __bpf_fault_handle_page_fault,
	.handle_wp_fault = __bpf_fault_handle_wp_fault,
};

/*
 * Apply or resolve write-protection on a page range registered with
 * bpf_fault WP.  Caller must not hold the mmap lock.
 */
int bpf_fault_wp_range(struct mm_struct *mm, unsigned long start,
		       unsigned long len, bool enable_wp)
{
	unsigned long end = start + len;
	unsigned long _start, _end;
	struct vm_area_struct *dst_vma;
	long err;
	VMA_ITERATOR(vmi, mm, start);

	if (bpf_fault_validate_range(mm, start, len))
		return -EINVAL;

	if (!mmget_not_zero(mm))
		return -ESRCH;

	mmap_read_lock(mm);

	err = -ENOENT;
	for_each_vma_range(vmi, dst_vma, end) {
		unsigned int mm_cp_flags;
		struct mmu_gather tlb;

		if (!bpf_fault_wp(dst_vma)) {
			err = -ENOENT;
			break;
		}

		_start = max(dst_vma->vm_start, start);
		_end = min(dst_vma->vm_end, end);

		if (enable_wp)
			mm_cp_flags = MM_CP_UFFD_WP;
		else
			mm_cp_flags = MM_CP_UFFD_WP_RESOLVE;

		if (!enable_wp &&
		    vma_wants_manual_pte_write_upgrade(dst_vma))
			mm_cp_flags |= MM_CP_TRY_CHANGE_WRITABLE;

		tlb_gather_mmu(&tlb, mm);
		err = change_protection(&tlb, dst_vma, _start, _end, mm_cp_flags);
		tlb_finish_mmu(&tlb);

		if (err < 0)
			break;
		err = 0;
	}

	mmap_read_unlock(mm);
	mmput(mm);
	return err;
}

/*
 * BPF kfunc: apply or resolve write-protection on a page range.
 *
 * Called from a BPF struct_ops fault handler.  The faulting task's mmap
 * lock is not held on entry (handle_bpf_fault releases it before calling
 * the BPF program).
 */
__bpf_kfunc_start_defs();

__bpf_kfunc int bpf_fault_writeprotect(struct bpf_fault_ops_ctx *ctx,
					__u64 start, __u64 len, bool enable_wp)
{
	return bpf_fault_wp_range(current->mm, start, len, enable_wp);
}

__bpf_kfunc_end_defs();

BTF_KFUNCS_START(bpf_fault_kfunc_ids)
BTF_ID_FLAGS(func, bpf_fault_writeprotect, KF_SLEEPABLE)
BTF_KFUNCS_END(bpf_fault_kfunc_ids)

static const struct btf_kfunc_id_set bpf_fault_kfunc_set = {
	.owner = THIS_MODULE,
	.set   = &bpf_fault_kfunc_ids,
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

	ret = register_btf_kfunc_id_set(BPF_PROG_TYPE_STRUCT_OPS,
					&bpf_fault_kfunc_set);
	if (ret) {
		pr_err("bpf_fault: failed to register kfuncs: %d\n", ret);
		return ret;
	}

	return 0;
}
__initcall(bpf_fault_init);
