#include <types.h>
#include <error.h>

#include <kernel/mem.h>
#include <kernel/sched.h>

pid_t sys_wait(int *rstatus)
{
	/* LAB 5: your code here. */

	if (list_is_empty(&cur_task->task_children)) return -ECHILD;

	if (!list_is_empty(&cur_task->task_zombies)) {
	  struct list *node, *next;
	  struct task * task;
	  pid_t destroyed_task;
	  list_foreach_safe(&cur_task->task_zombies, node, next) {
	    task = container_of(node, struct task,task_node);
	    destroyed_task = task->task_pid;
      cprintf("FFFreeing %d\n", task->task_pid);
      task_free(task);
	    return destroyed_task;
	  }
	} else {
	  list_remove(&cur_task->task_node);
    cur_task->task_status = TASK_NOT_RUNNABLE;
    sched_yield();
	}

	panic("sys_wait not yet implemented\n");
	return -ENOSYS;
}

pid_t sys_waitpid(pid_t pid, int *rstatus, int opts)
{
	/* LAB 5: your code here. */

  if (list_is_empty(&cur_task->task_children)) return -ECHILD;
  if (pid <= 0) return -ECHILD;

  if (!list_is_empty(&cur_task->task_zombies)) {
    struct list *node, *next;
    struct task * task;
    list_foreach_safe(&cur_task->task_zombies, node, next) {
      task = container_of(node, struct task,task_node);
      if (task->task_pid == pid) {
        cprintf("FFFreeing %d\n", task->task_pid);
        task_free(task);
        return pid;
      }
    }
  } else {
    cur_task->task_wait = pid2task(pid, 0);
    cur_task->task_status = TASK_NOT_RUNNABLE;
    list_remove(&cur_task->task_node);
    sched_yield();
  }

	panic("sys_waitpid not yet implemented\n");
	return -ENOSYS;
}

