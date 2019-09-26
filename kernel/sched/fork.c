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
	pid_t pid;
	/* first allocate a task struct for the child process */
	clone = task_alloc(task->task_pid);
	/* setup task */
	clone->task_type = task->task_type;
	/* copy register state */
	memcpy(&clone->task_frame, &task->task_frame, sizeof(task->task_frame));
	/* copy VMAs TODO*/
	/* copy page tables TODO*/
	/* add process to runqueue */
	list_insert_after(&runq, &clone->task_node);

	panic("task_clone not yet implemented\n");
	return NULL;
}

pid_t sys_fork(void)
{
	/* LAB 5: your code here. */
	struct task * clone;
	clone = task_clone(cur_task);
	panic("sys_fork not yet implemented\n");
	return -ENOSYS;
}

