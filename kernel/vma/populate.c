#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Checks the flags in udata against the flags of the VMA to check appropriate
 * permissions. If the permissions are all right, this function populates the
 * address range [base, base + size) with physical pages. If the VMA is backed
 * by an executable, the data is copied over. Then the protection of the
 * physical pages is adjusted to match the permissions of the VMA.
 */
int do_populate_vma(struct task *task, void *base, size_t size,
	struct vma *vma, void *udata)
{
	/* LAB 4: your code here. */

	if (vma->vm_flags & *((int *) udata)) {
	  return -1;
	}

	// Add pages to be able to write and read
	populate_region(task->task_pml4, base, size,
	    PAGE_PRESENT | PAGE_WRITE | vma->vm_flags);

	// If this is not an anonymous vma
	// TODO: Is this exclusive to executables?
	if (vma->vm_src) {
    // Get source file
	  struct elf * exe_file = (struct elf *) vma->vm_src;

	  // Check if it is a valid executable
    if (exe_file->e_magic == ELF_MAGIC) {
      memcpy(base, vma->vm_src, vma->vm_len);
    }
	}

  // Change the protection of physical pages according to vma
	protect_region(task->task_pml4, base, size, vma->vm_flags);

	return 0;
}

/* Populates the VMAs for the given address range [base, base + size) by
 * backing the VMAs with physical pages.
 */
int populate_vma_range(struct task *task, void *base, size_t size, int flags)
{
	return walk_vma_range(task, base, size, do_populate_vma, &flags);
}

