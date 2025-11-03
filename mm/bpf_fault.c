#include <linux/init.h>
#include <linux/slab.h>
#include <linux/userfaultfd_k.h>

static struct kmem_cache *bpf_fault_ctx_cachep __ro_after_init;

vm_fault_t handle_bpf_fault(struct vm_fault *vmf)
{
	struct bpf_fault_ctx *ctx;
	vm_fault_t ret = VM_FAULT_SIGBUS;
	struct vm_area_struct *vma = vmf->vma;
	struct mm_struct *mm = vma->vm_mm;

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

	/* take the reference before dropping the mmap_lock */
	//userfaultfd_ctx_get(ctx);

	release_fault_lock(vmf);

	// Set up BPF context
	// Call BPF program
	// Handle BPF program return value (userfaultfd_copy)

	/*
	 * ctx may go away after this if the userfault pseudo fd is
	 * already released.
	 */
	//userfaultfd_ctx_put(ctx);

out:
	return ret;
}

static int __init bpf_fault_init(void)
{
	bpf_fault_ctx_cachep = kmem_cache_create(
		"bpf_fault_ctx_cachep", sizeof(struct bpf_fault_ctx), 0,
		SLAB_HWCACHE_ALIGN | SLAB_PANIC, NULL);

	return 0;
}
__initcall(bpf_fault_init);
