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
	struct list *node;
	struct task *task;

	if(nuser_tasks == 0 && list_is_empty(&runq)) {
		sched_halt();
	} else {
		node = list_head(&runq); 
		cprintf("tasks %d : %p\n", nuser_tasks, node);
		task = container_of(node, struct task, task_node);
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

