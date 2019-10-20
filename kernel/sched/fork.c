#include <cpu.h>
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

struct fork_info {
  struct vma * vma;

};

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

extern struct spinlock runq_lock;

/**
 * This is just a deep copy that creates private ptables for all 4 levels
 * The leaves will point to same physical pages, only the tables will be
 * private to the process.
 *
 * @param src
 * @param dst
 */
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
  list_init(&clone->task_zombies);

#ifndef USE_BIG_KERNEL_LOCK
  spin_lock(&task->task_lock);
#endif
  list_insert_after(&task->task_children, &clone->task_child);

  /* setup task */
	clone->task_type = task->task_type;
	/* copy register state */

	memcpy(&clone->task_frame, &task->task_frame, sizeof(task->task_frame));

  /* copy page tables */
  copy_deep_ptables(task->task_pml4, clone->task_pml4);

  /* copy VMAs */
	list_foreach(&task->task_mmap, node) {
		vma = container_of(node, struct vma, vm_mmap);
		/* add the vma to clone */
		struct vma * exe_vma = add_executable_vma_v2(clone, vma->vm_name, (void *)vma->vm_base,
				(vma->vm_end - vma->vm_base), vma->vm_flags, vma->vm_src, vma->vm_len, vma->page_addr);

		if(!exe_vma) panic("Can't add exe vma\n");

		// Force stack to be mapped since it is going to be used to pop things
	  if(strcmp(exe_vma->vm_name, "stack") == 0) {
	    // Insert new pages on existing stacks address in clone process
	    populate_vma_range(clone, exe_vma->vm_base,
	        exe_vma->vm_end - exe_vma->vm_base, exe_vma->vm_flags);

	    // Get the page from clone
	    struct page_info * new_stack = page_lookup(clone->task_pml4,
	        (void *)USTACK_TOP - PAGE_SIZE, NULL);

	    // Copy to clone's stack vaddr from parent task's stack
	    memcpy(page2kva(new_stack), (void *)USTACK_TOP - PAGE_SIZE, PAGE_SIZE);

	  } else {
	    // Set the vmas to shared
      vma->is_shared = 1;
      exe_vma->is_shared = 1;

      struct vma * anon_vma = add_executable_vma(NULL, "shared anon", NULL, 0, 0, 0, 0);

      list_insert_after(&anon_vma->vma_list, &vma->vma_node);
      list_insert_after(&anon_vma->vma_list, &exe_vma->vma_node);

      if (vma->page_addr) {
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
	}

	/* add process to runqueue */

#ifndef USE_BIG_KERNEL_LOCK
  spin_lock(&runq_lock);
  list_insert_after(&runq, &clone->task_node);
  spin_unlock(&runq_lock);
  spin_unlock(&task->task_lock);
#else
  list_insert_after(&runq, &clone->task_node);
#endif

	return clone;
}

pid_t sys_fork(void)
{
	/* LAB 5: your code here. */
	struct task * clone;
	clone = task_clone(this_cpu->cpu_task);
	clone->task_frame.rax = 0;
	this_cpu->cpu_task->task_frame.rax = clone->task_pid;

	return  clone->task_pid;
}

int sys_exec(const char * file_name) {

  assert_user_mem(this_cpu->cpu_task, (void *) file_name, 1, 0);

  // Return if no binary
  if (!file_name) return -1;

  // Assume binary is valid
  uintptr_t binary = lookup_binary(file_name);

  struct list *node, *next;
  struct vma * old_vma;

  // Unmap all user things
  list_foreach_safe(&this_cpu->cpu_task->task_mmap, node, next) {
    old_vma = container_of(node, struct vma, vm_mmap);
    unmap_vma_range(this_cpu->cpu_task, old_vma->vm_base, old_vma->vm_end - old_vma->vm_base);
  }

  // Load new image into task
  task_load_elf(this_cpu->cpu_task, (uint8_t *)binary);

  // Remove task from runq
  list_remove(&this_cpu->cpu_task->task_node);
  // If context switch will done this task will be saved to runq
  // Otherwise, this same task will be called again
  sched_yield();
  return 0;
}

/* define macros */
#define PASTE3(x, y, z) x ## y ## z
#define GETBINARY(name) PASTE3(_binary_obj_user_, name, _start)
/* define user binary locations */
void _binary_obj_user_badsegment_start();
void _binary_obj_user_basicfork_start();
void _binary_obj_user_breakpoint_start();
void _binary_obj_user_cowfork_start();
void _binary_obj_user_divzero_start();
void _binary_obj_user_dontneed_start();
void _binary_obj_user_evilchild_start();
void _binary_obj_user_evilhello_start();
void _binary_obj_user_evilmadvise_start();
void _binary_obj_user_evilmmap_start();
void _binary_obj_user_evilmprotect_start();
void _binary_obj_user_evilmunmap_start();
void _binary_obj_user_faultexec_start();
void _binary_obj_user_faultwrite_start();
void _binary_obj_user_hello_start();
void _binary_obj_user_kernelexec_start();
void _binary_obj_user_kernelread_start();
void _binary_obj_user_kernelwrite_start();
void _binary_obj_user_lazyvma_start();
void _binary_obj_user_mapexec_start();
void _binary_obj_user_mapfixed_start();
void _binary_obj_user_mapleft_start();
void _binary_obj_user_mapnone_start();
void _binary_obj_user_mapnull_start();
void _binary_obj_user_mapright_start();
void _binary_obj_user_mapwrite_start();
void _binary_obj_user_mergevma_start();
void _binary_obj_user_mmap_start();
void _binary_obj_user_mprotect_start();
void _binary_obj_user_munmap_start();
void _binary_obj_user_mustneed_start();
void _binary_obj_user_nullexec_start();
void _binary_obj_user_nullhello_start();
void _binary_obj_user_nullread_start();
void _binary_obj_user_nullwrite_start();
void _binary_obj_user_overflowhello_start();
void _binary_obj_user_persistnone_start();
void _binary_obj_user_protexec_start();
void _binary_obj_user_protnone_start();
void _binary_obj_user_protwrite_start();
void _binary_obj_user_reaper_start();
void _binary_obj_user_softint_start();
void _binary_obj_user_splitvma_start();
void _binary_obj_user_testbss_start();
void _binary_obj_user_thp_start();
void _binary_obj_user_unmapleft_start();
void _binary_obj_user_unmapright_start();
void _binary_obj_user_unmaptext_start();
void _binary_obj_user_vma_start();
void _binary_obj_user_wait_start();
void _binary_obj_user_waitnone_start();
void _binary_obj_user_waitself_start();
void _binary_obj_user_willneed_start();
void _binary_obj_user_yield_start();

/* lookup function */
uintptr_t lookup_binary(const char * file_name) {
	if(strcmp(file_name, "badsegment") == 0) return (uintptr_t)GETBINARY(badsegment);
	if(strcmp(file_name, "basicfork") == 0) return (uintptr_t)GETBINARY(basicfork);
	if(strcmp(file_name, "breakpoint") == 0) return (uintptr_t)GETBINARY(breakpoint);
	if(strcmp(file_name, "cowfork") == 0) return (uintptr_t)GETBINARY(cowfork);
	if(strcmp(file_name, "divzero") == 0) return (uintptr_t)GETBINARY(divzero);
	if(strcmp(file_name, "dontneed") == 0) return (uintptr_t)GETBINARY(dontneed);
	if(strcmp(file_name, "evilchild") == 0) return (uintptr_t)GETBINARY(evilchild);
	if(strcmp(file_name, "evilhello") == 0) return (uintptr_t)GETBINARY(evilhello);
	if(strcmp(file_name, "evilmadvise") == 0) return (uintptr_t)GETBINARY(evilmadvise);
	if(strcmp(file_name, "evilmmap") == 0) return (uintptr_t)GETBINARY(evilmmap);
	if(strcmp(file_name, "evilmprotect") == 0) return (uintptr_t)GETBINARY(evilmprotect);
	if(strcmp(file_name, "evilmunmap") == 0) return (uintptr_t)GETBINARY(evilmunmap);
	if(strcmp(file_name, "faultexec") == 0) return (uintptr_t)GETBINARY(faultexec);
	if(strcmp(file_name, "faultwrite") == 0) return (uintptr_t)GETBINARY(faultwrite);
	if(strcmp(file_name, "hello") == 0) return (uintptr_t)GETBINARY(hello);
	if(strcmp(file_name, "kernelexec") == 0) return (uintptr_t)GETBINARY(kernelexec);
	if(strcmp(file_name, "kernelread") == 0) return (uintptr_t)GETBINARY(kernelread);
	if(strcmp(file_name, "kernelwrite") == 0) return (uintptr_t)GETBINARY(kernelwrite);
	if(strcmp(file_name, "lazyvma") == 0) return (uintptr_t)GETBINARY(lazyvma);
	if(strcmp(file_name, "mapexec") == 0) return (uintptr_t)GETBINARY(mapexec);
	if(strcmp(file_name, "mapfixed") == 0) return (uintptr_t)GETBINARY(mapfixed);
	if(strcmp(file_name, "mapleft") == 0) return (uintptr_t)GETBINARY(mapleft);
	if(strcmp(file_name, "mapnone") == 0) return (uintptr_t)GETBINARY(mapnone);
	if(strcmp(file_name, "mapnull") == 0) return (uintptr_t)GETBINARY(mapnull);
	if(strcmp(file_name, "mapright") == 0) return (uintptr_t)GETBINARY(mapright);
	if(strcmp(file_name, "mapwrite") == 0) return (uintptr_t)GETBINARY(mapwrite);
	if(strcmp(file_name, "mergevma") == 0) return (uintptr_t)GETBINARY(mergevma);
	if(strcmp(file_name, "mmap") == 0) return (uintptr_t)GETBINARY(mmap);
	if(strcmp(file_name, "mprotect") == 0) return (uintptr_t)GETBINARY(mprotect);
	if(strcmp(file_name, "munmap") == 0) return (uintptr_t)GETBINARY(munmap);
	if(strcmp(file_name, "mustneed") == 0) return (uintptr_t)GETBINARY(mustneed);
	if(strcmp(file_name, "nullexec") == 0) return (uintptr_t)GETBINARY(nullexec);
	if(strcmp(file_name, "nullhello") == 0) return (uintptr_t)GETBINARY(nullhello);
	if(strcmp(file_name, "nullread") == 0) return (uintptr_t)GETBINARY(nullread);
	if(strcmp(file_name, "nullwrite") == 0) return (uintptr_t)GETBINARY(nullwrite);
	if(strcmp(file_name, "overflowhello") == 0) return (uintptr_t)GETBINARY(overflowhello);
	if(strcmp(file_name, "persistnone") == 0) return (uintptr_t)GETBINARY(persistnone);
	if(strcmp(file_name, "protexec") == 0) return (uintptr_t)GETBINARY(protexec);
	if(strcmp(file_name, "protnone") == 0) return (uintptr_t)GETBINARY(protnone);
	if(strcmp(file_name, "protwrite") == 0) return (uintptr_t)GETBINARY(protwrite);
	if(strcmp(file_name, "reaper") == 0) return (uintptr_t)GETBINARY(reaper);
	if(strcmp(file_name, "softint") == 0) return (uintptr_t)GETBINARY(softint);
	if(strcmp(file_name, "splitvma") == 0) return (uintptr_t)GETBINARY(splitvma);
	if(strcmp(file_name, "testbss") == 0) return (uintptr_t)GETBINARY(testbss);
	if(strcmp(file_name, "thp") == 0) return (uintptr_t)GETBINARY(thp);
	if(strcmp(file_name, "unmapleft") == 0) return (uintptr_t)GETBINARY(unmapleft);
	if(strcmp(file_name, "unmapright") == 0) return (uintptr_t)GETBINARY(unmapright);
	if(strcmp(file_name, "unmaptext") == 0) return (uintptr_t)GETBINARY(unmaptext);
	if(strcmp(file_name, "vma") == 0) return (uintptr_t)GETBINARY(vma);
	if(strcmp(file_name, "wait") == 0) return (uintptr_t)GETBINARY(wait);
	if(strcmp(file_name, "waitnone") == 0) return (uintptr_t)GETBINARY(waitnone);
	if(strcmp(file_name, "waitself") == 0) return (uintptr_t)GETBINARY(waitself);
	if(strcmp(file_name, "willneed") == 0) return (uintptr_t)GETBINARY(willneed);
	if(strcmp(file_name, "yield") == 0) return (uintptr_t)GETBINARY(yield);
	return 0x0;
}


