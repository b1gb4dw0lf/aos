#include <types.h>
#include <cpu.h>
#include <error.h>

#include <kernel/mem.h>
#include <kernel/sched.h>

pid_t sys_wait(int *rstatus)
{
	/* LAB 5: your code here. */

	cprintf("Hello\n");
  cprintf("CPU %d - Wait %d\n", this_cpu->cpu_id, this_cpu->cpu_task->task_pid);
  spin_lock(&this_cpu->cpu_task->task_lock);

	if (list_is_empty(&this_cpu->cpu_task->task_children)) {
    spin_unlock(&this_cpu->cpu_task->task_lock);
	  return -ECHILD;
	}

	struct list *node, *next;
	struct task * task;
  pid_t removed_item;

  list_foreach_safe(&this_cpu->cpu_task->task_zombies, node, next) {
    task = container_of(node, struct task, task_node);
    removed_item = task->task_pid;
    task_free(task);
    spin_unlock(&this_cpu->cpu_task->task_lock);
    return removed_item;
  }

  list_remove(&this_cpu->cpu_task->task_node);

  this_cpu->cpu_task->task_status = TASK_NOT_RUNNABLE;
  this_cpu->cpu_task = NULL;

  spin_unlock(&this_cpu->cpu_task->task_lock);
  sched_yield();

	return -ECHILD;
}

pid_t sys_waitpid(pid_t pid, int *rstatus, int opts)
{
	/* LAB 5: your code here. */

  // If current task does not have any children to wait on
  if (pid <= 0 || !pid2task(pid, 0)) {
    // We are not dealing with process groups and
    // we assume this will be not called with pid -1 since
    // it would be same as sys_wait
    // If specified pid does not exist
    return -ECHILD;
  }

	struct task * task = pid2task(pid, 0);

  if (this_cpu->cpu_task && this_cpu->cpu_task == task) {
    return -ECHILD;
  }

  struct task * parent = pid2task(task->task_ppid, 0);

  if (!parent || parent->task_pid == 0 || parent->task_pid != this_cpu->cpu_task->task_pid) {
	  return -ECHILD;
	}

  spin_lock(&parent->task_lock);

  pid_t removed_item = task->task_pid;

  if (task->task_status == TASK_DYING) {
    task_free(task);
    spin_unlock(&parent->task_lock);
    return removed_item;
  }

  list_remove(&parent->task_node);
  parent->task_status = TASK_NOT_RUNNABLE;
  this_cpu->cpu_task = NULL;

  spin_unlock(&parent->task_lock);
  sched_yield();

	return -ENOSYS;
}

