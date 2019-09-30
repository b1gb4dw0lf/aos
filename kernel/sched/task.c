#include <error.h>
#include <string.h>
#include <paging.h>
#include <task.h>
#include <cpu.h>

#include <kernel/monitor.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <kernel/vma.h>

pid_t pid_max = 1 << 16;
struct task **tasks = (struct task **)PIDMAP_BASE;
size_t nuser_tasks = 0;
extern struct list runq;

/* Looks up the respective task for a given PID.
 * If check_perm is non-zero, this function checks if the PID maps to the
 * current task or if the current task is the parent of the task that the PID
 * maps to.
 */
struct task *pid2task(pid_t pid, int check_perm)
{
	struct task *task;
	
	/* PID 0 is the current task. */
	if (pid == 0) {
		return cur_task;
	}

	/* Limit the PID. */
	if (pid >= pid_max) {
		return NULL;
	}

	/* Look up the task in the PID map. */
	task = tasks[pid];

	/* No such mapping found. */
	if (!task) {
		return NULL;
	}

	/* If we don't have to do a permission check, we can simply return the
	 * task.
	 */
	if (!check_perm) {
		return task;
	}

	/* Check if the task is the current task or if the current task is the
	 * parent. If not, then the current task has insufficient permissions.
	 */
	if (task != cur_task && task->task_ppid != cur_task->task_pid) {
		return NULL;
	}

	return task;
}


#define STRIP_ENTRY(x) ROUNDDOWN(x & ~PAGE_NO_EXEC & ~PAGE_HUGE & ~ PAGE_PRESENT & ~PAGE_WRITE, PAGE_SIZE)
void task_init(void)
{
	/* Allocate an array of pointers at PIDMAP_BASE to be able to map PIDs
	 * to tasks.
	 */

	size_t total_pages = (pid_max * sizeof(struct task *)) / PAGE_SIZE;
	for (size_t i = 0; i < total_pages; ++i) {
    struct page_info * page = page_alloc(ALLOC_ZERO);
    page_insert(kernel_pml4, page,
        (void *)PIDMAP_BASE + (i * PAGE_SIZE),
        PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC);
	}
	/* LAB 3: your code here. */
}

/* Sets up the virtual address space for the task. */
static int task_setup_vas(struct task *task)
{
	struct page_info *page;

	/* Allocate a page for the page table. */
	page = page_alloc(ALLOC_ZERO);

	if (!page) {
		return -ENOMEM;
	}

	++page->pp_ref;

	/* Now set task->task_pml4 and initialize the page table.
	 * Can you use kernel_pml4 as a template?
	 */

	task->task_pml4 = page2kva(page);

  // For every pml4 entry
  for (int i = 0; i < 512; ++i) {

    if (!(kernel_pml4->entries[i] & PAGE_PRESENT)) continue;

    struct page_table * pdpt = (struct page_table *) KADDR(STRIP_ENTRY(kernel_pml4->entries[i]));

    ptbl_alloc(&task->task_pml4->entries[i], 0, 0, NULL);
    struct page_table *new_pdpt = (struct page_table *) KADDR(STRIP_ENTRY(task->task_pml4->entries[i]));

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

	return 0;
}

/* Allocates and initializes a new task.
 * On success, the new task is returned.
 */
struct task *task_alloc(pid_t ppid)
{
  cprintf("Allocating task\n");
	struct task *task;
	pid_t pid;

	/* Allocate a new task struct. */
	task = kmalloc(sizeof *task);

	if (!task) {
		return NULL;
	}

	/* Set up the virtual address space for the task. */
	if (task_setup_vas(task) < 0) {
		kfree(task);
		return NULL;
	}

	/* Find a free PID for the task in the PID mapping and associate the
	 * task with that PID.
	 */
	for (pid = 1; pid < pid_max; ++pid) {
    if (!tasks[pid]) {

      tasks[pid] = task;
			task->task_pid = pid;
			break;
		}
	}

	/* We are out of PIDs. */
	if (pid == pid_max) {
		kfree(task);
		return NULL;
	}

	/* Set up the task. */
	task->task_ppid = ppid;
	task->task_type = TASK_TYPE_USER;
	task->task_status = TASK_RUNNABLE;
	task->task_runs = 0;

	memset(&task->task_frame, 0, sizeof task->task_frame);

	task->task_frame.ds = GDT_UDATA | 3;
	task->task_frame.ss = GDT_UDATA | 3;
	task->task_frame.rsp = USTACK_TOP;
	task->task_frame.cs = GDT_UCODE | 3;

	/* You will set task->task_frame.rip later. */

	cprintf("[PID %5u] New task with PID %u\n",
	        cur_task ? cur_task->task_pid : 0, task->task_pid);

	return task;
}

/* Sets up the initial program binary, stack and processor flags for a user
 * process.
 * This function is ONLY called during kernel initialization, before running
 * the first user-mode environment.
 *
 * This function loads all loadable segments from the ELF binary image into the
 * task's user memory, starting at the appropriate virtual addresses indicated
 * in the ELF program header.
 * At the same time it clears to zero any portions of these segments that are
 * marked in the program header as being mapped but not actually present in the
 * ELF file, i.e., the program's .bss section.
 *
 * All this is very similar to what our boot loader does, except the boot
 * loader also needs to read the code from disk. Take a look at boot/main.c to
 * get some ideas.
 *
 * Finally, this function maps one page for the program's initial stack.
 */
static void task_load_elf(struct task *task, uint8_t *binary)
{
	/* Hints:
	 * - Load each program segment into virtual memory at the address
	 *   specified in the ELF section header.
	 * - You should only load segments with type ELF_PROG_LOAD.
	 * - Each segment's virtual address can be found in p_va and its
	 *   size in memory can be found in p_memsz.
	 * - The p_filesz bytes from the ELF binary, starting at binary +
	 *   p_offset, should be copied to virtual address p_va.
	 * - Any remaining memory bytes should be zero.
	 * - Use populate_region() and protect_region().
	 * - Check for malicious input.
	 *
	 * Loading the segments is much simpler if you can move data directly
	 * into the virtual addresses stored in the ELF binary.
	 * So in which address space should we be operating during this
	 * function?
	 *
	 * You must also do something with the entry point of the program, to
	 * make sure that the task starts executing there.
	 */

	/* LAB 3: your code here. */
	load_pml4((void *)PADDR(task->task_pml4));

	// Get elf file
	struct elf * elf_file = (struct elf *) binary;

  // Check if it is a valid elf file
  if (elf_file->e_magic != ELF_MAGIC) panic("This is not a ELF file!");

  // Get the program header
	struct elf_proghdr *ph = (struct elf_proghdr*) (binary + elf_file->e_phoff);

  // Get total amount of program headers
	size_t p_headers = elf_file->e_phnum;
  int flags = 0;

  task->task_frame.rip = elf_file->e_entry;

  load_pml4((void *) PADDR(task->task_pml4));

  struct elf_proghdr * eph = ph + elf_file->e_phnum;
  // Iterate through program segments and map and copy
  for (; ph < eph; ph++) {
    if (ph->p_type != ELF_PROG_LOAD || ph->p_va == 0) continue;

    flags = 0;

    if (ph->p_flags & ELF_PROG_FLAG_READ) flags |= VM_READ;
    if (ph->p_flags & ELF_PROG_FLAG_WRITE) flags |= VM_WRITE;
    if (ph->p_flags & ELF_PROG_FLAG_EXEC) flags |= VM_EXEC;

    char * name = "";

    if ((flags & VM_READ) && (flags & VM_WRITE) && !(flags & VM_EXEC)) name = ".data";
    if ((flags & VM_READ) && !(flags & VM_WRITE) && !(flags & VM_EXEC)) name = ".rodata";
    if ((flags & VM_READ) && !(flags & VM_WRITE) && (flags & VM_EXEC)) name = ".text";

    struct vma * exe_vma = add_executable_vma(task, name, (void *) ph->p_pa,
        ph->p_memsz, flags, binary + ph->p_offset, ph->p_filesz);

    if (!exe_vma) panic("Can't add executable vma\n");
  }

  uint64_t stack_flags = VM_READ | VM_WRITE;
	add_anonymous_vma(task, "stack", (void *) USTACK_TOP - PAGE_SIZE, PAGE_SIZE, stack_flags);

	load_pml4((void *)PADDR(kernel_pml4));
}

/* Allocates a new task with task_alloc(), loads the named ELF binary using
 * task_load_elf() and sets its task type.
 * If the task is a user task, increment the number of user tasks.
 * This function is ONLY called during kernel initialization, before running
 * the first user-mode task.
 * The new task's parent PID is set to 0.
 */
void task_create(uint8_t *binary, enum task_type type)
{
  struct task * task = task_alloc(0);
  rb_init(&task->task_rb);
  list_init(&task->task_mmap);
  task_load_elf(task, binary);

  if (task->task_type == TASK_TYPE_USER) nuser_tasks++;
	/* LAB 3: your code here. */
	/* LAB 5: your code here. */
	//panic("task_create not yet updated\n");
	list_push(&runq, &task->task_node); //add process to run queue
	list_init(&task->task_children);
}

/* Free the task and all of the memory that is used by it.
 */
void task_free(struct task *task)
{
	struct task *waiting;

	/* LAB 5: your code here. */
	/* If we are freeing the current task, switch to the kernel_pml4
	 * before freeing the page tables, just in case the page gets re-used.
	 */

	/*
	cprintf("Freeing children\n");
	struct list * node, * next;
	list_foreach_safe(&task->task_children, node, next) {
	  struct task * child = container_of(node, struct task, task_child);
	  task_free(child);
	}*/

	if (task == cur_task) {
		load_pml4((struct page_table *)PADDR(kernel_pml4));
	}

	/* Unmap the task from the PID map. */
	tasks[task->task_pid] = NULL;

	/* Unmap the user pages. */
	unmap_user_pages(task->task_pml4);

	// Remove vmas
	free_vmas(task);

  nuser_tasks--;
  list_remove(&task->task_node);


  /* Note the task's demise. */
  cprintf("[PID %5u] Freed task with PID %d\n", cur_task ? cur_task->task_pid : 0,
          task->task_pid);

  if (cur_task->task_pid == task->task_pid) {
    cur_task = NULL;
  }

  /* Free the task. */
  kfree(task);

}

/* Frees the task. If the task is the currently running task, then this
 * function runs a new task (and does not return to the caller).
 */
void task_destroy(struct task *task)
{
	/* else return */

  cprintf("Destroyed the only task - nothing more to do!\n");

  if (task->task_pid == cur_task->task_pid) {
    task_free(task);
	  sched_yield();
	} else {
    task_free(task);
  }

  /* LAB 5: your code here. */
}

/*
 * Restores the register values in the trap frame with the iretq or sysretq
 * instruction. This exits the kernel and starts executing the code of some
 * task.
 *
 * This function does not return.
 */
void task_pop_frame(struct int_frame *frame)
{
	switch (frame->int_no) {
#ifdef LAB3_SYSCALL
	case 0x80: sysret64(frame); break;
#endif
	default: iret64(frame); break;
	}

	panic("We should have gone back to userspace!");
}

/* Context switch from the current task to the provided task.
 * Note: if this is the first call to task_run(), cur_task is NULL.
 *
 * This function does not return.
 */
void task_run(struct task *task)
{
	/*
	 * Step 1: If this is a context switch (a new task is running):
	 *     1. Set the current task (if any) back to
	 *        TASK_RUNNABLE if it is TASK_RUNNING (think about
	 *        what other states it can be in),
	 *     2. Set 'cur_task' to the new task,
	 *     3. Set its status to TASK_RUNNING,
	 *     4. Update its 'task_runs' counter,
	 *     5. Use load_pml4() to switch to its address space.
	 * Step 2: Use task_pop_frame() to restore the task's
	 *     registers and drop into user mode in the
	 *     task.
	 *
	 * Hint: This function loads the new task's state from
	 *  e->task_frame.  Go back through the code you wrote above
	 *  and make sure you have set the relevant parts of
	 *  e->task_frame to sensible values.
	 */

	if (cur_task) {
    if (cur_task->task_status == TASK_RUNNING) {
      cur_task->task_status = TASK_RUNNABLE;
    }
  }

	if (cur_task && cur_task->task_pid != task->task_pid) {
	  list_insert_after(&runq, &cur_task->task_node);
  }

  cur_task = task;
  cur_task->task_status = TASK_RUNNING;
  cur_task->task_runs++;
  load_pml4((struct page_table *) PADDR(task->task_pml4));
  task_pop_frame(&task->task_frame);

	/* LAB 3: Your code here. */
	panic("task should be running!");
}

