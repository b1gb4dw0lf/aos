#include <types.h>
#include <cpu.h>
#include <list.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/paging.h>

#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>

struct list runq;

extern struct list dead_tasks;
extern struct spinlock dead_tasks_lock;

#ifndef USE_BIG_KERNEL_LOCK
struct spinlock runq_lock = {
#ifdef DBEUG_SPINLOCK
	.name = "runq_lock",
#endif
};
#endif

extern size_t nuser_tasks;

#ifdef USE_BIG_KERNEL_LOCK
extern struct spinlock kernel_lock;
#endif

void sched_init(void)
{
	list_init(&runq);
}

void sched_init_mp(void)
{
	/* LAB 6: your code here. */
	list_init(&this_cpu->runq);
	list_init(&this_cpu->nextq);
	this_cpu->runq_len = 0;
	this_cpu->nextq_len = 0;
	this_cpu->cpu_task = NULL;
}

void display_currents(void) {
  cprintf("Currents:\n");
  for (int i = 0; i < ncpus; ++i) {
    if (cpus[i].cpu_task) {
      cprintf("CPU %d - PID %d\n", cpus[i].cpu_id, cpus[i].cpu_task->task_pid);
    }
  }
}

size_t get_from_parent(size_t max) {
  struct list * node;
  size_t i = 0;

  for (i = 0; i < max; ++i) {
    node = list_pop_left(&runq);

    if (!node) {
      return i;
    };

    list_insert_after(&this_cpu->nextq, node);
    this_cpu->nextq_len++;
  }

  return i;
}

size_t pass_to_parent(size_t max) {
  struct list * node;
  size_t i = 0;

  for (i = 0; i < max; ++i) {
    node = list_pop(&this_cpu->nextq);

    if (!node) {
      return i;
    };

    this_cpu->nextq_len--;
    list_insert_after(&runq, node);
  }

  return i;
}

void swap_queue() {
  struct list * node;
  size_t i = 0;

  for (i = 0; i < this_cpu->nextq_len; ++i) {
    node = list_pop_left(&this_cpu->nextq);

    if (!node) {
      break;
    };

    list_insert_after(&this_cpu->runq, node);
    this_cpu->runq_len++;
  }
  this_cpu->nextq_len = 0;
}

void print_work_sets () {
  struct list * node;
  struct page_info * page;

  spin_lock(&working_set_lock);
  list_foreach(&working_set,node) {
    page = container_of(node, struct page_info, lru_node);
    cprintf("Active - Addr: %p Ref: %p Order: %d\n", page2pa(page), page->pp_ref, page->pp_order);
  }
  spin_unlock(&working_set_lock);

  spin_lock(&inactive_set_lock);
  list_foreach(&inactive_set,node) {
    page = container_of(node, struct page_info, lru_node);
    cprintf("Inactive - Addr: %p Ref: %p Order: %d\n", page2pa(page), page->pp_ref, page->pp_order);
  }
  spin_unlock(&inactive_set_lock);
}

/**
 * This will be either called from syscalls or init sides
 * Caller needs to acquire a lock
 */
void sched_yield(void)
{
	/* LAB 5: your code here. */
	struct list *node, * func_runq;
	struct task *task;

#ifndef USE_BIG_KERNEL_LOCK
  func_runq = &this_cpu->runq;


  if (list_is_empty(&this_cpu->runq)) {
    spin_lock(&runq_lock);
    size_t queue_size = 1;

    if (this_cpu->nextq_len > queue_size) {
      pass_to_parent(this_cpu->nextq_len - queue_size);
    } else if (this_cpu->nextq_len < queue_size) {
      get_from_parent(queue_size - this_cpu->nextq_len);
    }

    swap_queue();
    spin_unlock(&runq_lock);
  }


#else
  func_runq = &runq;
#endif

	if(list_is_empty(func_runq) && this_cpu->cpu_task == NULL) {
	  sched_halt();
	} else if (list_is_empty(func_runq) && this_cpu->cpu_task) {

	  // If current task has been killed by some other task
	  if (this_cpu->cpu_task->task_pid == 0) {
      this_cpu->cpu_task = NULL;
	    sched_halt();
	  }

    task_run(this_cpu->cpu_task);
	}else {
    node = list_pop_left(func_runq);
    task = container_of(node, struct task, task_node);

    task->task_cpunum = this_cpu->cpu_id;

#ifndef USE_BIG_KERNEL_LOCK
    this_cpu->runq_len--;
#else
    nuser_tasks--;
#endif

    task_run(task);
	}
}

int check_running() {
  for (int i = 0; i < ncpus; ++i) {
    if (cpus[i].cpu_status != CPU_HALTED) return 1;
  }
  return 0;
}

extern int should_exit;
/* For now jump into the kernel monitor. */
void sched_halt()
{
  xchg(&this_cpu->cpu_status, CPU_HALTED);

#ifdef USE_BIG_KERNEL_LOCK
  spin_unlock(&kernel_lock);
#endif

  if (list_is_empty(&runq) && boot_cpu->cpu_status == CPU_HALTED) {
    if (this_cpu->cpu_id == boot_cpu->cpu_id && !check_running()) {
      asm volatile("cli\n");

      spin_lock(&dead_tasks_lock);
      while (!list_is_empty(&dead_tasks)) {
        struct task * task = container_of(list_pop_left(&dead_tasks), struct task, task_node);
        spin_lock(&task->task_lock);
        if (list_is_empty(&task->task_children)) {
          task_free(task);
        } else {
          spin_unlock(&task->task_lock);
        }
      }
      if (holding(&dead_tasks_lock)) {
        spin_unlock(&dead_tasks_lock);
      }

      while (1) {
        monitor(NULL);
      }
    } else if (this_cpu->cpu_id != boot_cpu->cpu_id) {
      asm volatile(
        "cli\n"
        "hlt\n");
    }
  }

  asm volatile(
  "mov $0, %%rbp\n"
  "mov %0, %%rsp\n"
  "push $0\n"
  "push $0\n"
  "sti\n"
  "1:\n"
  "hlt\n" :: "a"(this_cpu->cpu_tss.rsp[0]));
}

