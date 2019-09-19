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
	mov %ds, %rax
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
	/* restore previous state */
	popq %rax
	mov %rax, %ds
	popq %r15
	popq %r14
	popq %r13
	popq %r12
	popq %r11
	popq %r10
	popq %r9
	popq %r8
	popq %rdi
	popq %rsi
	popq %rbp
	popq %rbx
	popq %rdx
	popq %rcx
	popq %rax
	/* iret should have the  required data on the stack */
	iretq


.global syscall64
syscall64:
	/* syscall args : rdi rsi, rdx, r10, r8, r9, rbp */
	/* LAB 3: your code here. */
	/* Store the userspace stack pointer in the per-cpu struct. */
	/* assumption : ring 3 right now */
  swapgs
	movq %rsp, %gs:CPU_TSS_RSP3
	/* Load the kernel stack pointer from the per-cpu struct. */
  movq %gs:CPU_TSS_RSP0, %rsp
	/* load int frame location */
	pushq %r15 /* store r15 temporarily */
	addq $16, %rsp 
	popq %r15
	pushq %r15
	subq $16, %rsp /* r15 at top of stack */
	/* store all wanted register */
	movq %rcx, 0x70(%r15)/* user space return pointer */
	movq %rax, 0x78(%r15) /* system call number */
	movq %rbp, 0x58(%r15)

	movq %rbx, 0x58(%r15)
	movq %r11, 0x28(%r15)
	movq %r12, 0x20(%r15)
	movq %r13, 0x18(%r15)
	movq %r14, 0x10(%r15)
	mov %cs, 0x98(%r15)
	mov %ss, 0xb0(%r15)
	mov %ds, 0x0(%r15)
	/* should consist of everything thats callee-preserved : */
	/* rbp, rbx and from r12 to r15, flags,[ CS/ SS ?] */
	/* V restore r15 state while also storing it */
	popq %r14
	movq %r14, 0x8(%r15)
	movq 0x10(%r15), %r14
	movq 0x8(%r15), %r15

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
	/* set DS register */
	mov 0x0(%rbx), %ds
	/* set other register */
	mov 0x8(%rbx), %r15
	mov 0x10(%rbx), %r14
	mov 0x18(%rbx), %r13
	mov 0x20(%rbx), %r12
	mov 0x28(%rbx), %r11
	mov 0x30(%rbx), %r10
	mov 0x38(%rbx), %r9
	mov 0x40(%rbx), %r8
	mov 0x48(%rbx), %rdi
	mov 0x50(%rbx), %rsi
	mov 0x58(%rbx), %rbp
	mov 0x68(%rbx), %rdx
	mov 0x70(%rbx), %rcx
	mov 0x78(%rbx), %rax
	mov 0x60(%rbx), %rbx 
	/* Return from the interrupt. */
	addq $16, %rsp
	iretq

.global sysret64
sysret64:
	/* LAB 3: your code here. */
	/* Recover the register state. */
	/* not from syscall64: dont forget syscall res is in rax */
	/* should consist of everything thats callee-preserved : */
  /* rbp, rbx and from r12 to r15, flags,[ CS/ SS ?] */
  /* V restore r15 state while also storing it */
	movq 0x78(%rbx), %rax
	movq 0x70(%rbx), %rcx
	movq 0x8(%rbx), %r15
	movq 0x10(%rbx), %r14
	movq 0x18(%rbx), %r13
	movq 0x20(%rbx), %r12
	movq 0x28(%rbx), %r11
	//mov 0x98(%rbx), %cs
	//mov 0xb0(%rbx), %ss
	//mov 0x0(%rbx), %ds

	/* restore RSP */
	movq %gs:CPU_TSS_RSP3, %rsp
	swapgs
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
ISR_NOERRCODE 128
