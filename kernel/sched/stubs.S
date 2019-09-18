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

	/* Recover the segments. */

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
	/* offset 0x8 * 1 + 8 + 7 + 2 then the first one*/
	/* pushq SS at offset 0x90(RIP) + 8+8+8+8*/
	/* pushq rsp at offset 0x90(RIP) + 8+8+8*/
	/* pushq EFLAGS? at offset 0x90(RIP) + 8+8*/
	/* pushq CS at offset 0x90(RIP) + 8*/
	/* pushq RIP at offset 0x90(RIP)  */
	pushq 0xb0(%rbx)
	pushq 0xa8(%rbx)
	pushq 0xa0(%rbx)
	pushq 0x98(%rbx)
	pushq 0x90(%rbx) 
	/* Return from the interrupt. */
	/*addq $16, %rsp*/
	iretq

.global sysret64
sysret64:
	/* LAB 3: your code here. */
	/* Recover the register state. */

	/* Return from the system call. */
	sysretq

