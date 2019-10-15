#include <kernel/sched.h>

extern pid_t pid_max;
extern struct task **tasks;

/**
 * Calculates resident set size
 * @param struct task
 * @return size_t
 */
size_t get_mm_rss(struct task * task) {
  size_t rss = 0;

  struct list * node, * next;
  struct vma * vma = NULL;

  // Get all mapped memory
  // Includes anon + file + shared page size
  list_foreach_safe(&task->task_mmap, node, next) {
    vma = container_of(node, struct vma, vm_mmap);
    if (vma->page_addr) {
      // It is mapped
      rss += vma->vm_end - vma->vm_base;
    }
  }

  return rss;
}

/**
 * Searches for the task with highest rss heuritstic in global tasks list
 * @return struct task
 */
struct task * get_task_to_kill() {
  struct task * max_mem_user = NULL;
  size_t max_mem_usage = 0, mem_usage = 0;

  for (pid_t i = 0; i < pid_max; ++i) {
    if (tasks[i]) {
      spin_lock(&tasks[i]->task_lock);
      if ((mem_usage = get_mm_rss(tasks[i])) > max_mem_usage) {
        max_mem_user = tasks[i];
        max_mem_usage = mem_usage;
      }
      spin_unlock(&tasks[i]->task_lock);
    }
  }

  return max_mem_user;
}


