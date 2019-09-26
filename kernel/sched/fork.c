#include <error.h>
#include <list.h>

#include <kernel/console.h>
#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>
#include <kernel/vma.h>

extern struct list runq;
extern struct task *task_alloc(pid_t ppid);

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
	/* setup task */
	clone->task_type = task->task_type;
	/* copy register state */
	memcpy(&clone->task_frame, &task->task_frame, sizeof(task->task_frame));
	/* copy VMAs TODO*/
	list_foreach(&task->task_mmap, node) {
		vma = container_of(node, struct vma, vm_mmap);
		/* add the vma to clone */
		struct vma * exe_vma = add_executable_vma(clone, vma->vm_name, (void *)vma->vm_base,
				(vma->vm_end - vma->vm_base), vma->vm_flags, vma->vm_src, vma->vm_len);
		if(!exe_vma) panic("Can't add exe vma\n");
	}

	/* copy page tables TODO*/
	/* add process to runqueue */
	list_insert_after(&runq, &clone->task_node);

	//panic("task_clone not yet implemented\n");
	return clone;
}

pid_t sys_fork(void)
{
	/* LAB 5: your code here. */
	struct task * clone;
	clone = task_clone(cur_task);
	return clone->task_pid;
}

