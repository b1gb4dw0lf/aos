#include <task.h>
#include <vma.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Removes the given VMA from the given task. */
void remove_vma(struct task *task, struct vma *vma)
{
	if (!task || !vma) {
		return;
	}

	rb_remove(&task->task_rb, &vma->vm_rb);
	rb_node_init(&vma->vm_rb);
	list_remove(&vma->vm_mmap);
}

/* Frees all the VMAs for the given task. */
void free_vmas(struct task *task)
{
	/* LAB 4: your code here. */

	struct list * node, * next;
	struct vma * vma;
	list_foreach_safe(&task->task_mmap, node, next) {
    vma = container_of(node, struct vma, vm_mmap);
    remove_vma(task, vma);
	}
}

/* Splits the VMA into the address range [base, base + size) and removes the
 * resulting VMA and any physical pages that back the VMA.
 */
int do_remove_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{

  // If the range is as big as the vma and contains the addr range
  if (base >= vma->vm_base && (base + size) < vma->vm_end &&
      (vma->vm_end - vma->vm_base) == ROUNDUP(size, PAGE_SIZE)) {

    remove_vma(task, vma);
    return 0;

  } else if (base >= vma->vm_base && (base + size) < vma->vm_end) {
    // Range does not span whole vma, split needed

    struct vma * rhs = split_vma(task, vma, ROUNDDOWN(base, PAGE_SIZE));

    if (!rhs) return -1;

    // If the range is a chunk in the middle
    if (rhs->vm_end > ROUNDUP(base + size, PAGE_SIZE)) {
      struct vma * rrhs = split_vma(task, rhs, ROUNDUP(base + size, PAGE_SIZE));
      if (!rrhs) return -1;
    }

    remove_vma(task, rhs);
    unmap_vma_range(task, rhs->vm_base, rhs->vm_end - rhs->vm_base);

    return 0;
  }

	/* LAB 4: your code here. */
	return -1;
}

/* Removes the VMAs and any physical pages backing those VMAs for the given
 * address range [base, base + size).
 */
int remove_vma_range(struct task *task, void *base, size_t size)
{
	return walk_vma_range(task, base, size, do_remove_vma, NULL);
}

/* Removes any non-dirty physical pages for the given address range
 * [base, base + size) within the VMA.
 */
int do_unmap_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
	/* LAB 4: your code here. */

	struct page_info * page = NULL;
	for (void * addr = base; addr < vma->vm_end; addr += PAGE_SIZE) {
	  if ((page = page_lookup(task->task_pml4, addr, NULL))) {
	    page_decref(page);
	  }
	}

	return 0;
}

/* Removes any non-dirty physical pages within the address range
 * [base, base + size).
 */
int unmap_vma_range(struct task *task, void *base, size_t size)
{
	return walk_vma_range(task, base, size, do_unmap_vma, NULL);
}

