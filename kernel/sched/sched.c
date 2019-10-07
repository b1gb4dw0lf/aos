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
#ifdef DEBUG_SPINLOCK
	.name = "runq_lock",
#endif
};
#endif

extern size_t nuser_tasks;

void sched_init(void)
{
	list_init(&runq);
	spin_init(&runq_lock, "runq_lock");
	spin_lock(&runq_lock);
}

void sched_init_mp(void)
{
	/* LAB 6: your code here. */
	list_init(&this_cpu->runq);
	this_cpu->runq_len = 0;
}

void sched_get_lock(void) {
  if (!holding(&BIG_KERNEL_LOCK)) {
    spin_lock(&BIG_KERNEL_LOCK);
  }
}

void sched_release_lock(void) {
  if (holding(&BIG_KERNEL_LOCK)) {
    spin_unlock(&BIG_KERNEL_LOCK);
  }
}

void sched_get_runq(void) {
  if (!holding(&runq_lock)) {
    spin_lock(&runq_lock);
  }
}

void sched_release_runq(void) {
  if (holding(&runq_lock)) {
    spin_unlock(&runq_lock);
  }
}

/* Runs the next runnable task. */
void sched_yield(void)
{
	/* LAB 5: your code here. */
	struct list *node, *temp;
	struct task *task, *temp_task;


	#ifdef USE_BIG_KERNEL_LOCK
	sched_get_lock();
	#endif
	#ifndef USE_BIG_KERNEL_LOCK
  sched_get_runq();
	#endif

  if(list_is_empty(&runq) && cur_task == NULL) {

		#ifdef USE_BIG_KERNEL_LOCK
		sched_release_lock();
		#else
    sched_release_runq();
		#endif

    sched_halt();
	} else if (list_is_empty(&runq) && cur_task) {

		#ifndef USE_BIG_KERNEL_LOCK
    sched_release_runq();
		#endif
		cur_task->task_cpunum = this_cpu->cpu_id;
    task_run(cur_task);
	}else {
    node = list_pop_left(&runq);
    task = container_of(node, struct task, task_node);
    nuser_tasks--;

		#ifndef USE_BIG_KERNEL_LOCK
    sched_release_runq();
		#endif
    task->task_cpunum = this_cpu->cpu_id;
		task_run(task);
	}
}

int check_any_running() {
  for (int i = 0; i < ncpus; ++i) {
    if (cpus[i].cpu_status != CPU_HALTED) {
      return 1;
    }
  }

  return 0;
}

/* For now jump into the kernel monitor. */
void sched_halt()
{
	#ifdef USE_BIG_KERNEL_LOCK
	while (1) {
		monitor(NULL);
	}
  #else

  spin_lock(&runq_lock);

  xchg(&this_cpu->cpu_status, CPU_HALTED);

  if (!cur_task && list_is_empty(&runq) && this_cpu->cpu_id == 0 && !check_any_running()) {
    spin_unlock(&runq_lock);
    asm volatile("cli\n");
    while (1) {
      monitor(NULL);
    }
	}


  spin_unlock(&runq_lock);
  asm volatile(
    "mov $0, %%rbp\n"
    "mov %0, %%rsp\n"
    "push $0\n"
    "push $0\n"
    "sti\n"
    "hlt\n" :: "a"(this_cpu->cpu_tss.rsp[0]));

	#endif
}

