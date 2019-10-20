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
	if (vma->vm_src && vma->vm_len > 0) {
    // Get source file

    cprintf("Total Len %d\n", vma->vm_len);

    // Real base can be 0x80020 while the base is 0x80000
    // So depending on the position of the page which can be get by
    // base - vma.vm_base, which means if the requested base is one page
    // to the right, then we will shift the copy dest or src by one too

    void * dst_base = vma->real_base >= base ? vma->real_base : base;
    void * src_base = vma->vm_src + (dst_base - vma->real_base);

    // Most of the time it'll be page size, but the end section will differ
    size_t copy_size = 0;

    // First piece
    if (dst_base == vma->real_base) {

      if (vma->vm_len > (PAGE_SIZE - (vma->real_base - vma->vm_base))) {
        copy_size = PAGE_SIZE - (vma->real_base - vma->vm_base);
      } else {
        copy_size = vma->vm_len;
      }

    } else {
      // Middle of the file
      // End of the file
      size_t remaining_len = vma->vm_len - (base - vma->real_base);
      copy_size = remaining_len > PAGE_SIZE ? PAGE_SIZE : remaining_len;
    }
    cprintf("Copying from %p to %p for %d real base: %p\n", src_base, dst_base, copy_size, vma->real_base);

    load_pml4((struct page_table *) PADDR(task->task_pml4));
    memcpy(dst_base, src_base, copy_size);
    cprintf("Copying done\n");
    load_pml4((struct page_table *) PADDR(kernel_pml4));
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

    page->vma = vma;

    add_fifo(&page->lru_node);
		list_push(&vma->allocated_pages, &page->pp_node);
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

