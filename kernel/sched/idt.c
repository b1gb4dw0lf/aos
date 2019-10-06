#include <assert.h>
#include <stdio.h>

#include <x86-64/asm.h>
#include <x86-64/gdt.h>
#include <x86-64/idt.h>

#include <kernel/acpi.h>
#include <kernel/sched/idt.h>
#include <kernel/monitor.h>
#include <kernel/sched/syscall.h>

#include <kernel/sched/task.h>
#include <kernel/vma.h>
#include <kernel/acpi.h>
#include <kernel/sched.h>

static const char *int_names[256] = {
	[INT_DIVIDE] = "Divide-by-Zero Error Exception (#DE)",
	[INT_DEBUG] = "Debug (#DB)",
	[INT_NMI] = "Non-Maskable Interrupt",
	[INT_BREAK] = "Breakpoint (#BP)",
	[INT_OVERFLOW] = "Overflow (#OF)",
	[INT_BOUND] = "Bound Range (#BR)",
	[INT_INVALID_OP] = "Invalid Opcode (#UD)",
	[INT_DEVICE] = "Device Not Available (#NM)",
	[INT_DOUBLE_FAULT] = "Double Fault (#DF)",
	[INT_TSS] = "Invalid TSS (#TS)",
	[INT_NO_SEG_PRESENT] = "Segment Not Present (#NP)",
	[INT_SS] = "Stack (#SS)",
	[INT_GPF] = "General Protection (#GP)",
	[INT_PAGE_FAULT] = "Page Fault (#PF)",
	[INT_FPU] = "x86 FPU Floating-Point (#MF)",
	[INT_ALIGNMENT] = "Alignment Check (#AC)",
	[INT_MCE] = "Machine Check (#MC)",
	[INT_SIMD] = "SIMD Floating-Point (#XF)",
	[INT_SECURITY] = "Security (#SX)",
};

static struct idt_entry entries[256];
static struct idtr idtr = {
	.limit = sizeof(entries) - 1,
	.entries = entries,
};

static const char *get_int_name(unsigned int_no)
{
	if (!int_names[int_no])
		return "Unknown Interrupt";

	return int_names[int_no];
}

void print_int_frame(struct int_frame *frame)
{
	cprintf("INT frame at %p\n", frame);

	/* Print the interrupt number and the name. */
	cprintf(" INT %u: %s\n",
		frame->int_no,
		get_int_name(frame->int_no));

	/* Print the error code. */
	switch (frame->int_no) {
	case INT_PAGE_FAULT:
		cprintf(" CR2 %p\n", read_cr2());
		cprintf(" ERR 0x%016llx (%s, %s, %s)\n",
			frame->err_code,
			frame->err_code & 4 ? "user" : "kernel",
			frame->err_code & 2 ? "write" : "read",
			frame->err_code & 1 ? "protection" : "not present");
		break;
	default:
		cprintf(" ERR 0x%016llx\n", frame->err_code);
	}

	/* Print the general-purpose registers. */
	cprintf(" RAX 0x%016llx"
		" RCX 0x%016llx"
		" RDX 0x%016llx"
		" RBX 0x%016llx\n"
		" RSP 0x%016llx"
		" RBP 0x%016llx"
		" RSI 0x%016llx"
		" RDI 0x%016llx\n"
		" R8  0x%016llx"
		" R9  0x%016llx"
		" R10 0x%016llx"
		" R11 0x%016llx\n"
		" R12 0x%016llx"
		" R13 0x%016llx"
		" R14 0x%016llx"
		" R15 0x%016llx\n",
		frame->rax, frame->rcx, frame->rdx, frame->rbx,
		frame->rsp, frame->rbp, frame->rsi, frame->rdi,
		frame->r8,  frame->r9,  frame->r10, frame->r11,
		frame->r12, frame->r13, frame->r14, frame->r15);

	/* Print the IP, segment selectors and the RFLAGS register. */
	cprintf(" RIP 0x%016llx"
		" RFL 0x%016llx\n"
		" CS  0x%04x"
		"            "
		" DS  0x%04x"
		"            "
		" SS  0x%04x\n",
		frame->rip, frame->rflags,
		frame->cs, frame->ds, frame->ss);
}
/* named in idt.h */
void isr0();
void isr1();
void isr2();
void isr3();
void isr4();
void isr5();
void isr6();
void isr7();
void isr8();
void isr10();
void isr11();
void isr12();
void isr13();
void isr14();
void isr16();
void isr17();
void isr18();
void isr19();
void isr30();
/* not named in idt.h */
void isr9();
void isr20();
void isr21();
/* Syscall */
void isr128();
/* irq */
void isr32();

/* Set up the interrupt handlers. */
void idt_init(void)
{
	set_idt_entry(&idtr.entries[INT_DIVIDE],				isr0, (IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE);//FAULT
	set_idt_entry(&idtr.entries[INT_DEBUG],					isr1, (IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE);//FAULT
	set_idt_entry(&idtr.entries[INT_NMI],						isr2, (IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE);//NOT APPLICCABLE
	set_idt_entry(&idtr.entries[INT_BREAK],					isr3, (IDT_PRESENT | IDT_TRAP_GATE32 | IDT_PRIVL(0x3)), GDT_KCODE);//TRAP
	set_idt_entry(&idtr.entries[INT_OVERFLOW],			isr4, (IDT_PRESENT | IDT_TRAP_GATE32), GDT_KCODE);//TRAP
	set_idt_entry(&idtr.entries[INT_BOUND],					isr5, (IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE);//PAGE FAULT?
	set_idt_entry(&idtr.entries[INT_INVALID_OP],		isr6, (IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE);//FAULT
	set_idt_entry(&idtr.entries[INT_DEVICE],				isr7, (IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE);//FAULT
	set_idt_entry(&idtr.entries[INT_DOUBLE_FAULT],	isr8, (IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //ABORT
	set_idt_entry(&idtr.entries[INT_TSS],						isr10,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //FAULT
	set_idt_entry(&idtr.entries[INT_NO_SEG_PRESENT],isr11,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //FAULT
	set_idt_entry(&idtr.entries[INT_SS],						isr12,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //FAULT
	set_idt_entry(&idtr.entries[INT_GPF],						isr13,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //FAULT
	set_idt_entry(&idtr.entries[INT_PAGE_FAULT],		isr14,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //FAULT
	set_idt_entry(&idtr.entries[INT_FPU],						isr16,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //FAULT
	set_idt_entry(&idtr.entries[INT_ALIGNMENT],			isr17,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //FAULT
	set_idt_entry(&idtr.entries[INT_MCE],						isr18,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //ABORT
	set_idt_entry(&idtr.entries[INT_SIMD],					isr19,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //FAULT
	set_idt_entry(&idtr.entries[INT_SECURITY],			isr30,(IDT_PRESENT | IDT_INT_GATE32 ), GDT_KCODE); //No description, FAULT
  /* reserved - not in intel manual*/
	set_idt_entry(&idtr.entries[9],				isr9, (IDT_PRESENT | IDT_INT_GATE32), GDT_KCODE); //ABORT - INTEL RESERVED
	set_idt_entry(&idtr.entries[20],			isr20,(IDT_PRESENT | IDT_INT_GATE32), GDT_KCODE); //Virtualizatio exception , FAULT
	set_idt_entry(&idtr.entries[21],			isr21,(IDT_PRESENT | IDT_INT_GATE32), GDT_KCODE); //No description, FAULT
	/* LAB 3: your code here. */
	/* syscall */
	set_idt_entry(&idtr.entries[INT_SYSCALL],				isr128, (IDT_PRESENT | IDT_INT_GATE32 | IDT_PRIVL(0x3)), GDT_KCODE);//TRAP

	/* set IRQ handlers */
	for (int i = 0; i < 15; i++) {
		set_idt_entry(&idtr.entries[IRQ_OFFSET + i], isr32, (IDT_PRESENT | IDT_INT_GATE32 | IDT_PRIVL(0x3)),GDT_KCODE);
	}
//	set_idt_entry(&idtr.entries[IRQ_TIMER],         isr32, (IDT_PRESENT | IDT_INT_GATE32 | IDT_PRIVL(0x3)), GDT_KCODE);
//	set_idt_entry(&idtr.entries[IRQ_OFFSET + IRQ_TIMER],         isr32, (IDT_PRESENT | IDT_INT_GATE32 | IDT_PRIVL(0x3)), GDT_KCODE);
	/*set_idt_entry(&idtr.entries[IRQ_OFFSET + IRQ_KBD],         irqtimer, (IDT_PRESENT | IDT_INT_GATE32), GDT_KCODE);
	set_idt_entry(&idtr.entries[IRQ_OFFSET + IRQ_SERIAL],         irqtimer, (IDT_PRESENT | IDT_INT_GATE32), GDT_KCODE);
	set_idt_entry(&idtr.entries[IRQ_OFFSET + IRQ_SPURIOUS],         irqtimer, (IDT_PRESENT | IDT_INT_GATE32), GDT_KCODE);*/
	load_idt(&idtr);
}

void idt_init_mp(void)
{
	/* LAB 6: your code here. */
	idt_init();
}

void int_dispatch(struct int_frame *frame)
{
	/* Handle processor exceptions:
	 *  - Fall through to the kernel monitor on a breakpoint.
	 *  - Dispatch page faults to page_fault_handler().
	 *  - Dispatch system calls to syscall().
	 */
	/* LAB 3: your code here. */
	switch (frame->int_no) {
    case INT_BREAK:
      monitor(frame);
			return;
    case INT_PAGE_FAULT:
      page_fault_handler(frame);
			return;
		case IRQ_TIMER:
		  lapic_eoi();
		  sched_yield();
    case INT_SYSCALL:
			frame->rax = (uint64_t)syscall(frame->rdi, frame->rsi, frame->rdx, frame->rcx, frame->r8, frame->r9, frame->rbp); //frame->rbp = 7th
			return;
  	default: break;
	}

	/* Unexpected trap: The user process or the kernel has a bug. */
	print_int_frame(frame);

	if (frame->cs == GDT_KCODE) {
		panic("unhandled interrupt in kernel");
	} else {
		task_destroy(cur_task);
		return;
	}
}

void int_handler(struct int_frame *frame)
{
	/* The task may have set DF and some versions of GCC rely on DF being
	 * clear. */
	asm volatile("cld" ::: "cc");

	/* Check if interrupts are disabled.
	 * If this assertion fails, DO NOT be tempted to fix it by inserting a
	 * "cli" in the interrupt path.
	 */
	assert(!(read_rflags() & FLAGS_IF));

	if ((frame->cs & 3) == 3) {
		/* Interrupt from user mode. */
		assert(cur_task);

		/* Copy interrupt frame (which is currently on the stack) into
		 * 'cur_task->task_frame', so that running the task will restart at
		 * the point of interrupt. */
		cur_task->task_frame = *frame;

		/* Avoid using the frame on the stack. */
		frame = &cur_task->task_frame;
	}

	/* Dispatch based on the type of interrupt that occurred. */
	int_dispatch(frame);

	/* Return to the current task, which should be running. */
	task_run(cur_task);
}

void page_fault_handler(struct int_frame *frame)
{
	void *fault_va;
	unsigned perm = frame->err_code;

	/* Read the CR2 register to find the faulting address. */
	fault_va = (void *)read_cr2();

	/* Handle kernel-mode page faults. */
	/* LAB 3: your code here. */
	if (!((frame->cs & 3) == 3)) {
		/* fault triggered from kernel mode */
		panic("Kernel mode page fault\n");
	}

	/* We have already handled kernel-mode exceptions, so if we get here, the
	 * page fault has happened in user mode.
	 */

	if (task_page_fault_handler(cur_task, fault_va, perm) == 0) {
	  task_run(cur_task);
	}

	/* Destroy the task that caused the fault. */
	cprintf("[PID %5u] user fault va %p ip %p\n",
		cur_task->task_pid, fault_va, frame->rip);
	print_int_frame(frame);
	task_destroy(cur_task);
}

