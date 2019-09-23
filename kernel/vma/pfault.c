#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Handles the page fault for a given task. */
int task_page_fault_handler(struct task *task, void *va, int flags)
{
	/* LAB 4: your code here. */
	// If it is a null pointer
	if (!va) return -1;

	struct vma * found = task_find_vma(task, va);

	// If it is not in vma
	if (!found) return -1;

  // If the faulting page is valid and in vma
  int vm_flags = 0;
	vm_flags |= flags & 2 ? PAGE_WRITE : PAGE_PRESENT;

	return populate_vma_range(task, found->vm_base, found->vm_end - found->vm_base, vm_flags);
}

