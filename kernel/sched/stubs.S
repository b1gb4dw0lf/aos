.section .text

#include <x86-64/gdt.h>
#include <x86-64/idt.h>
#include <x86-64/memory.h>

#include <cpu.h>

.macro ISR_NOERRCODE int_no
.global isr\int_no
isr\int_no:
	pushq $0
	pushq $\int_no
	jmp isr_common_stub
.endm

.macro ISR_ERRCODE int_no
.global isr\int_no
isr\int_no:
	pushq $\int_no
	jmp isr_common_stub
.endm

isr_common_stub:
	/* LAB 3: your code here. */
	/* Save the register state on the stack. */
	pushq %rax
	pushq %rcx
	pushq %rdx
	pushq %rbx
	pushq %rbp
	pushq %rsi
	pushq %rdi
	pushq %r8
	pushq %r9
	pushq %r10
	pushq %r11
	pushq %r12
	pushq %r13
	pushq %r14
	pushq %r15
	mov %ds, %ax
	pushq %rax
	/* push DS ; maybe mov %ax,%ds */
	/* Recover the segments. */
	mov $GDT_KDATA, %rax
	mov %ax, %ds
	mov %ax, %es
	/* Jump to the generic interrupt handler. */
	movq %rsp, %rdi
	/* push rsp as argument to the handler */
	pushq %rsp
	jmp int_handler
	/* should probably recover the registers after this by popping it all */

.global syscall64
syscall64:
	/* LAB 3: your code here. */
	/* Store the userspace stack pointer in the per-cpu struct. */

	/* Load the kernel stack pointer from the per-cpu struct. */

	/* Store the register state into the per-cpu struct. */

	/* Jump to the system call handler. */
	movq %r10, %rcx
	pushq %rbp
	pushq $0
	jmp syscall_handler

.global iret64
iret64:
	/* LAB 3: your code here. */
	/* Restore the register state. */
	/* offset 0x8 * 1 + 8 + 7 + 2 then the first one*/
	/* pushq SS at offset 0x90(RIP) + 8+8+8+8*/
	/* pushq rsp at offset 0x90(RIP) + 8+8+8*/
	/* pushq EFLAGS? at offset 0x90(RIP) + 8+8*/
	/* pushq CS at offset 0x90(RIP) + 8*/
	/* pushq RIP at offset 0x90(RIP)  */
	/* pushq int no */
	/* pushq err code */
	pushq 0xb0(%rbx)
	pushq 0xa8(%rbx)
	pushq 0xa0(%rbx)
	pushq 0x98(%rbx)
	pushq 0x90(%rbx) 
	pushq 0x88(%rbx)
	pushq 0x80(%rbx)
	mov 0x0(%rbx), %ds
	/* Return from the interrupt. */
	addq $16, %rsp
	iretq

.global sysret64
sysret64:
	/* LAB 3: your code here. */
	/* Recover the register state. */

	/* Return from the system call. */
	sysretq

// Define ISRs
ISR_NOERRCODE 0
ISR_NOERRCODE 1
ISR_NOERRCODE 2
ISR_NOERRCODE 3
ISR_NOERRCODE 4
ISR_NOERRCODE 5
ISR_NOERRCODE 6
ISR_NOERRCODE 7
ISR_NOERRCODE 8
ISR_NOERRCODE 9
ISR_ERRCODE 10
ISR_ERRCODE 11
ISR_ERRCODE 12
ISR_ERRCODE 13
ISR_ERRCODE 14
ISR_NOERRCODE 16
ISR_ERRCODE 17
ISR_NOERRCODE 18
ISR_NOERRCODE 19
ISR_NOERRCODE 20
ISR_ERRCODE 21
ISR_ERRCODE 30
ISR_NOERRCODE 32
