#include <types.h>
#include <list.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/paging.h>

#include <kernel/mem.h>
#include <kernel/monitor.h>
#include <kernel/sched.h>

struct list runq;

extern size_t nuser_tasks;

void sched_init(void)
{
	list_init(&runq);
}

/* Runs the next runnable task. */
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
	panic("sched_yield not yet implemented\n");
}

/* For now jump into the kernel monitor. */
void sched_halt()
{
	while (1) {
		monitor(NULL);
	}
}

