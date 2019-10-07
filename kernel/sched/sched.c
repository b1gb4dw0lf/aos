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
	spin_lock(&runq_lock);
	#endif

  if(list_is_empty(&runq) && cur_task == NULL) {

		#ifdef USE_BIG_KERNEL_LOCK
		sched_release_lock();
		#endif

		#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&runq_lock);
		#endif

    sched_halt();
	} else if (list_is_empty(&runq) && cur_task) {

		#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&runq_lock);
		#endif
		cur_task->task_cpunum = this_cpu->cpu_id;
    task_run(cur_task);
	}else {
    node = list_pop_left(&runq);
    task = container_of(node, struct task, task_node);
    nuser_tasks--;

		#ifndef USE_BIG_KERNEL_LOCK
		spin_unlock(&runq_lock);
		#endif
    task->task_cpunum = this_cpu->cpu_id;
		task_run(task);
	}
}

/* For now jump into the kernel monitor. */
void sched_halt()
{
	#ifdef USE_BIG_KERNEL_LOCK
	while (1) {
		monitor(NULL);
	}
	#endif

	#ifndef USE_BIG_KERNEL_LOCK
	if(this_cpu != boot_cpu) {
		while(1) {
		}
	} else {
		while(1) {
			monitor(NULL);
		}	
	}
	#endif
}

