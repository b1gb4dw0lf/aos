#include <task.h>
#include <vma.h>
#include <stdio.h>

#include <kernel/vma.h>

/* Given a task and two VMAs, checks if the VMAs are adjacent and compatible
 * for merging. If they are, then the VMAs are merged by removing the
 * right-hand side and extending the left-hand side by setting the end address
 * of the left-hand side to the end address of the right-hand side.
 */
struct vma *merge_vma(struct task *task, struct vma *lhs, struct vma *rhs)
{
	/* LAB 4: your code here. */

	cprintf("Merge: %p %p\n", lhs->vm_base, rhs->vm_base);
	if ((lhs->vm_end == rhs->vm_base) && (lhs->vm_flags == rhs->vm_flags)) {
	  lhs->vm_end = rhs->vm_end;
	  remove_vma(task, rhs);
	  return lhs;
	}

	return NULL;
}

/* Given a task and a VMA, this function attempts to merge the given VMA with
 * the previous and the next VMA. Returns the merged VMA or the original VMA if
 * the VMAs could not be merged.
 */
struct vma *merge_vmas(struct task *task, struct vma *vma)
{
	/* LAB 4: your code here. */

	struct vma * left_vma = NULL, * right_vma = NULL;

	left_vma = task_find_vma(task, vma->vm_base - PAGE_SIZE + 1);
	right_vma = task_find_vma(task, vma->vm_base + PAGE_SIZE + 1);


	if (left_vma && !left_vma->vm_src && (left_vma->vm_end == vma->vm_base) && (left_vma->vm_flags == vma->vm_flags)) {
    cprintf("Left? %c %p - %p\n", left_vma ? 'Y':'N', left_vma->vm_base, left_vma->vm_end);
    vma = merge_vma(task, left_vma, vma);
	}

  if (right_vma && !right_vma->vm_src && (right_vma->vm_base == vma->vm_end) && (right_vma->vm_flags == vma->vm_flags)) {
    cprintf("Right? %c %p - %p\n", right_vma ? 'Y':'N', right_vma->vm_base, right_vma->vm_end);
    vma = merge_vma(task, vma, right_vma);
  }

	return vma;
}

