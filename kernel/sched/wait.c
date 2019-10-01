#include <types.h>
#include <error.h>

#include <kernel/mem.h>
#include <kernel/sched.h>

pid_t sys_wait(int *rstatus)
{
	/* LAB 5: your code here. */

	if (list_is_empty(&cur_task->task_children)) return -ECHILD;

	struct list *node, *next;
	struct task * task;
  pid_t removed_item;

  list_foreach_safe(&cur_task->task_zombies, node, next) {
    task = container_of(node, struct task, task_node);
    removed_item = task->task_pid;
    task_free(task);
    return removed_item;
  }

  list_remove(&cur_task->task_node);
  cur_task->task_status = TASK_NOT_RUNNABLE;
  cur_task = NULL;
  sched_yield();

	return -ECHILD;
}

pid_t sys_waitpid(pid_t pid, int *rstatus, int opts)
{
	/* LAB 5: your code here. */
  if (list_is_empty(&cur_task->task_children)) return -ECHILD;
  if (pid <= 0) return -ECHILD;

  struct task * task = pid2task(pid, 0);
  pid_t removed_item = task->task_pid;

  if (task->task_status == TASK_DYING) {
    task_free(task);
    return removed_item;
  }

  list_remove(&cur_task->task_node);
  cur_task->task_status = TASK_NOT_RUNNABLE;
  cur_task = NULL;
  sched_yield();

	return -ENOSYS;
}

