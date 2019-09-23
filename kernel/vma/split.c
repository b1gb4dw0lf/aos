#include <task.h>
#include <vma.h>

#include <kernel/vma.h>
#include <kernel/mem.h>

/* Given a task and a VMA, this function splits the VMA at the given address
 * by setting the end address of original VMA to the given address and by
 * adding a new VMA with the given address as base.
 */
struct vma *split_vma(struct task *task, struct vma *lhs, void *addr)
{
	/* LAB 4: your code here. */
  size_t size = lhs->vm_end - addr;
  lhs->vm_end = ROUNDDOWN(addr, PAGE_SIZE); // Update end of original vma

	if (lhs->vm_src) {
	  cprintf("Splitting BACKED VMA\n");
    struct vma * new_vma = add_executable_vma(task, lhs->vm_name, addr, size, lhs->vm_flags,
	      lhs->vm_src + size, lhs->vm_len - (lhs->vm_end - lhs->vm_base));
    lhs->vm_len = lhs->vm_end - lhs->vm_base;
    return new_vma;
	} else {
    cprintf("Splitting ANON VMA\n");
    return add_anonymous_vma(task, lhs->vm_name, addr, size, lhs->vm_flags);
	}

	return NULL;
}

/* Given a task and a VMA, this function first splits the VMA into a left-hand
 * and right-hand side at address base. Then this function splits the
 * right-hand side or the original VMA, if no split happened, into a left-hand
 * and a right-hand side. This function finally returns the right-hand side of
 * the first split or the original VMA.
 */
struct vma *split_vmas(struct task *task, struct vma *vma, void *base, size_t size)
{
	/* LAB 4: your code here. */
	return vma;
}

