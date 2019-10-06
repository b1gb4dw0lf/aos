#include <x86-64/asm.h>

#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/mem.h>
#include <kernel/sched.h>

/* While boot_cpus() is booting a given CPU, it communicates the per-core stack
 * pointer that should be loaded by boot_ap().
 */
void *mpentry_kstack;

void boot_cpus(void)
{
	extern unsigned char boot_ap16[], boot_ap_end[];
	void *code;
	struct cpuinfo *cpu;

	/* Write entry code at the reserved page at MPENTRY_PADDR. */
	code = KADDR(MPENTRY_PADDR);
	memmove(code, KADDR((physaddr_t)boot_ap16), boot_ap_end - boot_ap16);

	/* Boot each CPU one at a time. */
	for (cpu = cpus; cpu < cpus + ncpus; ++cpu) {
		/* Skip the boot CPU */
		if (cpu == boot_cpu) {
			continue;
		}

		cprintf("Setting up kernel stack\n");
		/* Set up the kernel stack. */
		mpentry_kstack = (void *)cpu->cpu_tss.rsp[0];

		cprintf("Done\nStarting LAPIC\n");
		/* Start the CPU at boot_ap16(). */
		lapic_startup(cpu->cpu_id, PADDR(code));

		cprintf("Done\nWait until CPU starts\n");

		/* Wait until the CPU becomes ready. */
		while (cpu->cpu_status != CPU_STARTED);

		cprintf("Done\n");
	}
}

void mp_main(void)
{
  cprintf("Inside MP Main\n");

	/* Eable the NX-bit. */
	write_msr(MSR_EFER, read_msr(MSR_EFER) | MSR_EFER_NXE);

	/* Load the kernel PML4. */
	cprintf("Load PML4\n");

	asm volatile("movq %0, %%cr3\n" :: "r" (PADDR(kernel_pml4)));

	/* Load the per-CPU kernel stack. */
	asm volatile("movq %0, %%rsp\n" :: "r" (mpentry_kstack));

	cprintf("SMP: CPU %d starting\n", lapic_cpunum());

	/* LAB 6: your code here. */
	/* Initialize the local APIC. */
  lapic_init();
  cprintf("Initialized LAPIC\n");

	/* Set up segmentation, interrupts, system call support. */
  gdt_init_mp();
  idt_init_mp();
  syscall_init_mp();
  cprintf("Initialized GDT, IDT, SYSCALLs\n");

	/* Set up the per-CPU slab allocator. */
	kmem_init_mp();
	cprintf("Initialized KMEM\n");

	/* Set up the per-CPU scheduler. */
	sched_init_mp();
	cprintf("Initialized SCHED\n");

	/* Notify the main CPU that we started up. */
	xchg(&this_cpu->cpu_status, CPU_STARTED);
	cprintf("Notified creator\n");

	/* Schedule tasks. */
	sched_yield();
}

