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
	pushf
    pushq %r15
    pushq %r14
    pushq %r13
    pushq %r12
    pushq %r11
    pushq %r10
    pushq %r9
    pushq %r8
    pushq %rdi
    pushq %rsi
    pushq %rbp
    pushq %rbx
    pushq %rdx
    pushq %rcx
    pushq %rax
    pushq %rsp
	/* Recover the segments. */
	mov $GDT_KDATA, %rax
	mov %ax, %ds
	mov %ax, %es
	/* Jump to the generic interrupt handler. */
	movq %rsp, %rdi
	jmp int_handler

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
    pop %rsp
    pop %rax
    pop %rcx
    pop %rdx
    pop %rbx
    pop %rbp
    pop %rsi
    pop %rdi
    pop %r8
    pop %r9
    pop %r10
    pop %r11
    pop %r12
    pop %r13
    pop %r14
    pop %r15
    popf
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
ISR_ERRCODE 0
ISR_ERRCODE 1
ISR_ERRCODE 2
ISR_ERRCODE 3
ISR_ERRCODE 4
ISR_ERRCODE 5
ISR_ERRCODE 6
ISR_ERRCODE 7
ISR_ERRCODE 8
ISR_ERRCODE 9
ISR_ERRCODE 10
ISR_ERRCODE 11
ISR_ERRCODE 12
ISR_ERRCODE 13
ISR_ERRCODE 14
ISR_ERRCODE 15
ISR_ERRCODE 16
ISR_ERRCODE 17
ISR_ERRCODE 18
ISR_ERRCODE 19
ISR_ERRCODE 20
ISR_ERRCODE 21
ISR_ERRCODE 22
ISR_ERRCODE 23
ISR_ERRCODE 24
ISR_ERRCODE 25
ISR_ERRCODE 26
ISR_ERRCODE 27
ISR_ERRCODE 28
ISR_ERRCODE 29
ISR_ERRCODE 30
ISR_ERRCODE 31
ISR_ERRCODE 32
