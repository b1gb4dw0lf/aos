#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Handles the page fault for a given task. */
int task_page_fault_handler(struct task *task, void *va, int flags)
{
	/* LAB 4: your code here. */

	cprintf("Handle PID: %d PFAULT va: %p\n", task->task_pid, va);

  // User should not be asking for kernelspace
	//if (va >= (void *) KERNEL_LIM) return -1;

	cprintf("Looking for vma\n");

	// If the faulting page is valid and in vma
	struct vma * found = find_vma(NULL, NULL, &task->task_rb, va);

	if (!found) return -1;

	cprintf("Found vma\n");

	int vm_flags = 0;

	if (flags & PAGE_PRESENT) vm_flags |= VM_READ;
	if (flags & PAGE_WRITE) vm_flags |= VM_WRITE;
	if (!(flags & PAGE_NO_EXEC)) vm_flags |= VM_EXEC;

	populate_vma_range(task, found->vm_base, found->vm_end - found->vm_base, vm_flags);

	return -1;
}

