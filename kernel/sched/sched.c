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

extern struct spinlock kernel_lock;

void sched_init(void)
{
	list_init(&runq);
}

void sched_init_mp(void)
{
	/* LAB 6: your code here. */
	list_init(&this_cpu->runq);
	this_cpu->runq_len = 0;
}

/**
 * This will be either called from syscalls or init sides
 * Caller needs to acquire a lock
 */
void sched_yield(void)
{
	/* LAB 5: your code here. */
	struct list *node, *temp;
	struct task *task, *temp_task;

	if(list_is_empty(&runq) && cur_task == NULL) {
		sched_halt();
	} else if (list_is_empty(&runq) && cur_task) {
    task_run(cur_task);
	}else {
    node = list_pop_left(&runq);
    task = container_of(node, struct task, task_node);
    nuser_tasks--;
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

  if (list_is_empty(&runq) && boot_cpu->cpu_status == CPU_HALTED) {
    if (this_cpu->cpu_id == boot_cpu->cpu_id && !check_running()) {
      spin_unlock(&kernel_lock);
      asm volatile("cli\n");
      while (1) {
        monitor(NULL);
      }
    } else if (this_cpu->cpu_id != boot_cpu->cpu_id) {
      spin_unlock(&kernel_lock);
      asm volatile(
        "cli\n"
        "hlt\n");
    }
  }

  spin_unlock(&kernel_lock);
  asm volatile(
  "mov $0, %%rbp\n"
  "mov %0, %%rsp\n"
  "push $0\n"
  "push $0\n"
  "sti\n"
  "1:\n"
  "hlt\n" :: "a"(this_cpu->cpu_tss.rsp[0]));
}

