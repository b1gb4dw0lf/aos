#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>
#include <lib.h>

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

  int flags = *(int *) udata;

	uint64_t page_flags = 0;

	if (flags & PROT_READ) page_flags |= PAGE_PRESENT;
	if (flags & PROT_WRITE) page_flags |= PAGE_WRITE;
	if (!(flags & PROT_EXEC)) page_flags |= PAGE_NO_EXEC;

	if (((flags & PROT_WRITE) || (flags & PROT_EXEC)) && !(flags & PROT_READ)) {
	  cprintf("Returning -1\n");
	  return -1;
	}

	page_flags |= PAGE_USER;

  struct vma * s_vma = split_vmas(task, vma, base, size);
  s_vma->vm_flags = *((int *) udata);

	protect_region(task->task_pml4, base, size, page_flags);

	dump_page_tables(task->task_pml4, PAGE_HUGE);

	return 0;
}

/* Changes the protection flags of the VMAs for the given address range
 * [base, base + size).
 */
int protect_vma_range(struct task *task, void *base, size_t size, int flags)
{
	return walk_vma_range(task, base, size, do_protect_vma, &flags);
}

