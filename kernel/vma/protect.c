#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Changes the protection flags of the given VMA. Does nothing if the flags
 * would remain the same. Splits up the VMA into the address range
 * [base, base + size) and changes the protection of the physical pages backing
 * the VMA. Then attempts to merge the VMAs in case the protection became the
 * same as that of any of the adjacent VMAs.
 */
int do_protect_vma(struct task *task, void *base, size_t size, struct vma *vma,
	void *udata)
{
	/* LAB 4 (bonus): your code here. */

	struct vma * s_vma = split_vmas(task, vma, base, size);
	s_vma->vm_flags = *((int *) udata);

	uint64_t page_flags = 0;

	if (s_vma->vm_flags & VM_READ) page_flags |= PAGE_PRESENT;
	if (s_vma->vm_flags & VM_WRITE) page_flags |= PAGE_WRITE;
	if (!(s_vma->vm_flags & VM_EXEC)) page_flags |= PAGE_NO_EXEC;

	page_flags |= PAGE_USER;

	protect_region(task->task_pml4, base, size, page_flags);

	return 0;
}

/* Changes the protection flags of the VMAs for the given address range
 * [base, base + size).
 */
int protect_vma_range(struct task *task, void *base, size_t size, int flags)
{
	return walk_vma_range(task, base, size, do_protect_vma, &flags);
}

