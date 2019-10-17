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
	if (!(vma->vm_flags & *((int *) udata))) {
	  return -1;
	}

	// Add pages to be able to write and read
	populate_region(task->task_pml4, base, size,
	    PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC | PAGE_USER);

	// If this is not an anonymous vma
	if (vma->vm_src) {
    // Get source file
    memcpy(vma->real_base, vma->vm_src, vma->vm_len);
	}

	uint64_t page_flags = 0;

	// If vma range is shared make it read only
	if (!vma->is_shared) {
    if (vma->vm_flags & VM_READ) page_flags |= PAGE_PRESENT;
    if (vma->vm_flags & VM_WRITE) page_flags |= PAGE_WRITE;
    if (!(vma->vm_flags & VM_EXEC)) page_flags |= PAGE_NO_EXEC;
	} else {
	  page_flags |= PAGE_PRESENT;
	}

	page_flags |= PAGE_USER;

  // Change the protection of physical pages according to vma
	protect_region(task->task_pml4, base, size, page_flags);
	vma->page_addr = base; // Set this if mapped

	// Adds mapped pages to active or inactive sets
	// TODO: Should we make a distinciton between stack pages?
  struct page_info * page = NULL;
  for (void * s = base; s < (base + size); s+=PAGE_SIZE) {
    page = page_lookup(task->task_pml4, s, NULL);

    if (!page) continue;

    if (vma->vm_src) {
      insert_after_inactive(&page->lru_node);
    } else {
      insert_after_working(&page->lru_node);
    }
  }

	return 0;
}

/* Populates the VMAs for the given address range [base, base + size) by
 * backing the VMAs with physical pages.
 */
int populate_vma_range(struct task *task, void *base, size_t size, int flags)
{
	return walk_vma_range(task, base, size, do_populate_vma, &flags);
}

