#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Handles the page fault for a given task. */
int task_page_fault_handler(struct task *task, void *va, int flags)
{
	/* LAB 4: your code here. */

	cprintf("Handle PID: %d PFAULT va: %p\n", task->task_pid, va);

	if (!va) return -1;

	cprintf("Looking for vma\n");

	// If the faulting page is valid and in vma
	struct vma * found = find_vma(NULL, NULL, &task->task_rb, va);

	if (!found) return -1;

	int vm_flags = 0;

	vm_flags |= flags & 2 ? PAGE_WRITE : PAGE_PRESENT;

	return populate_vma_range(task, found->vm_base, found->vm_end - found->vm_base, vm_flags);
}

