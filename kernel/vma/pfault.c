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

  /* LAB 5: your code here. */
  if (found->page_addr) {
    // If it is mapped, it is probably a write on shared
    // address check flags and create a new entry?

    struct page_info * mapped_page = page_lookup(task->task_pml4, va, NULL);

    uint64_t page_flags = 0;
    if (found->vm_flags & VM_READ) page_flags |= PAGE_PRESENT;
    if (found->vm_flags & VM_WRITE) page_flags |= PAGE_WRITE;
    if (!(found->vm_flags & VM_EXEC)) page_flags |= PAGE_NO_EXEC;
    page_flags |= PAGE_USER;

    if (mapped_page->pp_ref > 1) {
      size_t range_size = found->vm_end - found->vm_base;
      struct page_info * new_page;

      if (range_size != HPAGE_SIZE) {
        for (size_t i = 0; i < range_size/PAGE_SIZE; ++i) {
          new_page = page_alloc(ALLOC_ZERO);
          memcpy(page2kva(new_page)  + (i * PAGE_SIZE),
              found->vm_base + (i * PAGE_SIZE), PAGE_SIZE);
          page_insert(task->task_pml4, new_page, found->vm_base  + (i * PAGE_SIZE), page_flags);
        }
        found->isShared = 0;
      } else {
        panic("HPage support not available yet.\n");
      }

      cprintf("Printing for PID %d\n", task->task_pid);
      dump_page_tables(task->task_pml4, PAGE_HUGE);

      return 0;
    } else { // If the page containing this region has only one ref
      cprintf("Only one ref\n");
      protect_region(task->task_pml4, found->vm_base,
          found->vm_end - found->vm_base, page_flags);
      found->isShared = 0;
      cprintf("Printing for PID %d\n", task->task_pid);
      dump_page_tables(task->task_pml4, PAGE_HUGE);
      return 0;
    }
  } else {
    cprintf("Populating range\n");
    return populate_vma_range(task, found->vm_base, found->vm_end - found->vm_base, vm_flags);
  }
}

