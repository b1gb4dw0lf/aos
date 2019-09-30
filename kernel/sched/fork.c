#include <error.h>
#include <list.h>

#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>
#include <kernel/vma.h>

extern struct list runq;
extern struct task *task_alloc(pid_t ppid);
#define STRIP_ENTRY(x) ROUNDDOWN(x & ~PAGE_NO_EXEC & ~PAGE_HUGE & ~ PAGE_PRESENT & ~PAGE_WRITE, PAGE_SIZE)

static int get_pte(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker *walker) {
  if ((*entry & PAGE_PRESENT)) {
    struct page_info * page = pa2page(STRIP_ENTRY(*entry));
    page->pp_ref += 1;
  }
  return 0;
}

static int get_pde(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker *walker) {
  if ((*entry & PAGE_HUGE) && (*entry & PAGE_PRESENT)) {
    struct page_info * page = pa2page(STRIP_ENTRY(*entry));
    page->pp_ref += 1;
  }
  return 0;
}

void increase_page_refs(struct page_table *pml4, void *va, size_t size,
                        uint64_t flags)
{
  struct page_walker walker = {
      .get_pte = get_pte,
      .get_pde = get_pde,
  };

  walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);
}

void copy_deep_ptables(struct page_table * src, struct page_table * dst) {
  // For every pml4 entry
  for (int i = 0; i < 512; ++i) {

    if (!(src->entries[i] & PAGE_PRESENT)) continue;

    struct page_table * pdpt = (struct page_table *) KADDR(STRIP_ENTRY(src->entries[i]));

    ptbl_alloc(&dst->entries[i], 0, 0, NULL);
    struct page_table *new_pdpt = (struct page_table *) KADDR(STRIP_ENTRY(dst->entries[i]));

    // For every pdpt entry
    for (int j = 0; j < 512; ++j) {

      if (!(pdpt->entries[j] & PAGE_PRESENT)) continue;

      struct page_table * pdir = (struct page_table *) KADDR(STRIP_ENTRY(pdpt->entries[j]));
      ptbl_alloc(&new_pdpt->entries[j], 0, 0, NULL);
      struct page_table * new_pdir = (struct page_table *) KADDR(STRIP_ENTRY(new_pdpt->entries[j]));

      // For every pdir entry
      for (int k = 0; k < 512; ++k) {

        if (!(pdir->entries[k] & PAGE_PRESENT)) continue;

        if (pdir->entries[k] & PAGE_HUGE) {
          new_pdir->entries[k] = pdir->entries[k];
          continue;
        }

        struct page_table * pt = (struct page_table *) KADDR(STRIP_ENTRY(pdir->entries[k]));
        ptbl_alloc(&new_pdir->entries[k], 0, 0, NULL);
        struct page_table * new_pt = (struct page_table *) KADDR(STRIP_ENTRY(new_pdir->entries[k]));

        // For every pt entry
        memcpy(new_pt, pt, PAGE_SIZE);
      }
    }
  }
}

/* Allocates a task struct for the child process and copies the register state,
 * the VMAs and the page tables. Once the child task has been set up, it is
 * added to the run queue.
 */
struct task *task_clone(struct task *task)
{
	/* LAB 5: your code here. */
	struct task * clone;
	struct list * node;
	struct vma * vma;
	/* first allocate a task struct for the child process */
	clone = task_alloc(task->task_pid);
	rb_init(&clone->task_rb);
  list_init(&clone->task_mmap);
  list_init(&clone->task_children);
  list_init(&clone->task_node);

  list_insert_after(&task->task_children, &clone->task_child);

  /* setup task */
	clone->task_type = task->task_type;
	/* copy register state */
	memcpy(&clone->task_frame, &task->task_frame, sizeof(task->task_frame));

  /* copy page tables TODO*/
  copy_deep_ptables(task->task_pml4, clone->task_pml4);

  /* copy VMAs TODO*/
	list_foreach(&task->task_mmap, node) {
		vma = container_of(node, struct vma, vm_mmap);
		/* add the vma to clone */
		struct vma * exe_vma = add_executable_vma(clone, vma->vm_name, (void *)vma->vm_base,
				(vma->vm_end - vma->vm_base), vma->vm_flags, vma->vm_src, vma->vm_len);
		// Should we add this to function?
		exe_vma->page_addr = vma->page_addr;

		if(!exe_vma) panic("Can't add exe vma\n");

	  if(strcmp(exe_vma->vm_name, "stack") == 0) {
	    populate_vma_range(clone, exe_vma->vm_base,
	        exe_vma->vm_end - exe_vma->vm_base, exe_vma->vm_flags);
	    struct page_info * new_stack = page_lookup(clone->task_pml4,
	        (void *)USTACK_TOP - PAGE_SIZE, NULL);
	    cprintf("Copying stack to %p\n", page2kva(new_stack));
	    memcpy(page2kva(new_stack), (void *)USTACK_TOP - PAGE_SIZE, PAGE_SIZE);

	  } else {
      vma->isShared = 1;
      exe_vma->isShared = 1;

	    // Increase refs if mapped
      increase_page_refs(clone->task_pml4, exe_vma->vm_base,
          exe_vma->vm_end - exe_vma->vm_base, 0);

      // Change shared pages' protection to read only
      protect_region(task->task_pml4, vma->vm_base,
          vma->vm_end - vma->vm_base, PAGE_PRESENT | PAGE_NO_EXEC | PAGE_USER);
      protect_region(clone->task_pml4, vma->vm_base,
          vma->vm_end - vma->vm_base, PAGE_PRESENT | PAGE_NO_EXEC | PAGE_USER);
    }
	}

	/* add process to runqueue */
  list_push(&runq, &clone->task_node);
	dump_page_tables(clone->task_pml4, PAGE_HUGE);

	return clone;
}

pid_t sys_fork(void)
{
	/* LAB 5: your code here. */
	struct task * clone;
	clone = task_clone(cur_task);
	return  clone->task_pid;
}

