#include <kernel/sched.h>

/**
 * Calculates resident set size
 * @param struct task
 * @return size_t
 */
size_t get_mm_rss(struct task * task) {
  size_t rss = 0;

  struct list * node, * next;
  struct vma * vma = NULL;

  spin_lock(&task->task_lock);

  // Get all mapped memory
  // Includes anon + file + shared page size
  list_foreach_safe(&task->task_mmap, node, next) {
    vma = container_of(node, struct vma, vm_mmap);
    if (vma->page_addr) {
      // It is mapped
      rss += vma->vm_end - vma->vm_base;
    }
  }

  spin_unlock(&task->task_lock);

  return rss;
}

struct task * get_task_to_kill(struct list * task_list) {

  return NULL;
}


