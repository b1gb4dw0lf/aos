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

	if (lhs->vm_src) {
	  panic("Splitting BACKED VMA\n");
	} else {
    struct vma *new_vma = kmalloc(sizeof(struct vma));
    new_vma->vm_flags = lhs->vm_flags;
    new_vma->vm_src = NULL;
    new_vma->vm_len = 0;
    new_vma->vm_name = lhs->vm_name;
    new_vma->vm_base = addr;
    new_vma->vm_end = lhs->vm_end;

    rb_node_init(&new_vma->vm_rb);

    if (insert_vma(task, new_vma) < 0) return NULL;
    lhs->vm_end = addr; // Update end of original vma

    return new_vma;
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
  if (vma->vm_end - vma->vm_base == size) return vma;

  if (vma->vm_base == base) { // Most left one
    split_vma(task, vma, base + size);
    return vma;
  } else {
    struct vma * s_vma = split_vma(task, vma, base);

    if (s_vma->vm_end - s_vma->vm_base == size) return s_vma;

    split_vma(task, s_vma, base + size);
    return s_vma;
  }
}

