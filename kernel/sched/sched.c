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
	this_cpu->runq_len = 0;
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

    list_insert_after(&this_cpu->runq, node);
    this_cpu->runq_len++;
  }

  return i;
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
#else
  func_runq = &runq;
#endif

	if(list_is_empty(func_runq) && this_cpu->cpu_task == NULL) {

#ifndef USE_BIG_KERNEL_LOCK
    spin_lock(&runq_lock);
    size_t len = get_from_parent(3);
    if (len == 0 || list_is_empty(func_runq)) {
      sched_halt();
    }
    spin_unlock(&runq_lock);
    sched_yield();
#endif

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

/* For now jump into the kernel monitor. */
void sched_halt()
{

  xchg(&this_cpu->cpu_status, CPU_HALTED);

#ifdef USE_BIG_KERNEL_LOCK
  spin_unlock(&kernel_lock);
#else
  spin_unlock(&runq_lock);
#endif

  if (list_is_empty(&runq) && boot_cpu->cpu_status == CPU_HALTED) {
    if (this_cpu->cpu_id == boot_cpu->cpu_id && !check_running()) {
      asm volatile("cli\n");
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

