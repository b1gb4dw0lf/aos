#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

#ifdef BONUS_LAB5
struct page_info * zeropage;
#endif

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

  /* LAB 5: your code here. */
  if (found->page_addr) {
    // If it is mapped, it is probably a write on shared
    // address check flags and create a new entry?

    uint64_t page_flags = 0;

    if(found->vm_flags & VM_READ) page_flags |= PAGE_PRESENT;
    if(found->vm_flags & VM_WRITE) page_flags |= PAGE_WRITE;
    if(!(found->vm_flags & VM_EXEC)) page_flags |= PAGE_NO_EXEC;
    page_flags |= PAGE_USER;

    if (!(page_flags & vm_flags)) return -1;

    struct page_info * page = page_lookup(task->task_pml4, found->vm_base, NULL);

    if (page->pp_ref > 1) { // Shared page create a new one
      struct page_info * new_page;
      if (page->pp_order == BUDDY_2M_PAGE) {
        // 1 - Create a new page
        new_page = page_alloc(ALLOC_HUGE | ALLOC_ZERO);
        // 2 - Copy page context into new one
        memcpy(page2kva(new_page), found->vm_base, HPAGE_SIZE);
        // 3 - Change the corresponding entry
        page_insert(task->task_pml4, new_page, found->vm_base, page_flags);

      } else {
        size_t num_of_pages = (found->vm_end - found->vm_base) / PAGE_SIZE;

        for (size_t i = 0; i < num_of_pages; ++i) {
          // 1 - Create a new page
          new_page = page_alloc(ALLOC_ZERO);
          // 2 - Copy page context into new one
          memcpy(page2kva(new_page), found->vm_base + (i * PAGE_SIZE), PAGE_SIZE);
          // 3 - Change the corresponding entry
          page_insert(task->task_pml4, new_page, found->vm_base + (i * PAGE_SIZE), page_flags);
        }
      }
      found->is_shared = 0;

    } else { // Only one ref change perms
      protect_region(task->task_pml4, found->vm_base,
                     found->vm_end - found->vm_base, page_flags);
    }

    return 0;
  } else { // If the range is not mapped
    #ifdef BONUS_LAB5
    if(!(flags & PAGE_WRITE) && !(found->vm_src)) { /* if vma is anonymous and request is a read */
      size_t num_of_pages = (found->vm_end - found->vm_base) / PAGE_SIZE; /* calculate range to zeropage */
      if(!zeropage) zeropage = page_alloc(ALLOC_ZERO); /* allocate the global zeropage if it hasnt been already */

      for (size_t i = 0; i < num_of_pages; ++i) { /* set all to zeropage */
        return page_insert(task->task_pml4, zeropage, (void *)found->vm_base + (i * PAGE_SIZE), PAGE_PRESENT | PAGE_NO_EXEC);
      }
    }
    #endif
    return populate_vma_range(task, found->vm_base, found->vm_end - found->vm_base, vm_flags);
  }
}

