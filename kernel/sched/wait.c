#include <types.h>
#include <cpu.h>
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

  // If current task does not have any children to wait on
	if (list_is_empty(&cur_task->task_children)) return -ECHILD;

	// We are not dealing with process groups and
	// we assume this will be not called with pid -1 since
	// it would be same as sys_wait
  if (pid <= 0) return -ECHILD;

  // If specified pid does not exist
  if (!pid2task(pid, 0)) return -ECHILD;

  size_t is_child_in = 0;
  struct list *node;
  struct task *child;

  // Check if it is an immediate childe
  list_foreach(&cur_task->task_children, node) {
    child = container_of(node, struct task, task_child);
    if (child->task_pid == pid) is_child_in = 1;
  }
  if (!is_child_in) return -ECHILD;

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

