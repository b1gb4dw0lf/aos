#
# Makefile fragment for JOS kernel.
# This is NOT a complete makefile;
# you must run GNU make in the top-level directory
# where the GNUmakefile is located.
#

OBJDIRS += kernel

# LAB 1 code
KERNEL_SRCFILES := \
	kernel/boot.S \
	kernel/console.c \
	kernel/main.c \
	kernel/monitor.c \
	kernel/pic.c \
	kernel/printf.c \
	kernel/mem/boot.c \
	kernel/mem/buddy.c \
	kernel/mem/init.c \
	kernel/tests/lab1.c \
	lib/list.c \
	lib/printfmt.c \
	lib/rbtree.c \
	lib/readline.c \
	lib/string.c

# LAB 2 code
KERNEL_SRCFILES += \
	kernel/mem/dump.c \
	kernel/mem/insert.c \
	kernel/mem/lookup.c \
	kernel/mem/map.c \
	kernel/mem/page.c \
	kernel/mem/ptbl.c \
	kernel/mem/remove.c \
	kernel/mem/tlb.c \
	kernel/mem/walk.c \
	kernel/tests/lab2.c

# LAB 3 code
KERNEL_SRCFILES += \
	kernel/mem/kmem.c \
	kernel/mem/populate.c \
	kernel/mem/protect.c \
	kernel/mem/slab.c \
	kernel/mem/user.c \
	kernel/sched/cpu.c \
	kernel/sched/gdt.c \
	kernel/sched/idt.c \
	kernel/sched/stubs.S \
	kernel/sched/syscall.c \
	kernel/sched/task.c \
	kernel/tests/lab3.c \

# LAB 3 binaries
KERNEL_BINFILES := \
	user/badsegment \
	user/breakpoint \
	user/divzero \
	user/evilhello \
	user/faultexec \
	user/faultwrite \
	user/kernelexec \
	user/kernelread \
	user/kernelwrite \
	user/hello \
	user/nullexec \
	user/nullhello \
	user/nullread \
	user/nullwrite \
	user/overflowhello \
	user/softint \
	user/testbss

# LAB 4 code
KERNEL_SRCFILES += \
	kernel/vma/find.c \
	kernel/vma/insert.c \
	kernel/vma/merge.c \
	kernel/vma/pfault.c \
	kernel/vma/populate.c \
	kernel/vma/protect.c \
	kernel/vma/remove.c \
	kernel/vma/show.c \
	kernel/vma/split.c \
	kernel/vma/syscall.c \
	kernel/vma/walk.c

KERNEL_BINFILES += \
	user/dontneed \
	user/evilmadvise \
	user/evilmmap \
	user/evilmprotect \
	user/evilmunmap \
	user/lazyvma \
	user/mapexec \
	user/mapfixed \
	user/mapleft \
	user/mapnone \
	user/mapnull \
	user/mapright \
	user/mapwrite \
	user/mmap \
	user/mergevma \
	user/mprotect \
	user/munmap \
	user/mustneed \
	user/persistnone \
	user/protexec \
	user/protnone \
	user/protwrite \
	user/splitvma \
	user/thp \
	user/unmapleft \
	user/unmapright \
	user/unmaptext \
	user/vma \
	user/willneed

# LAB 5 code
KERNEL_SRCFILES += \
	kernel/rtc.c \
	kernel/acpi/acpi.c \
	kernel/acpi/hpet.c \
	kernel/acpi/lapic.c \
	kernel/acpi/madt.c \
	kernel/sched/fork.c \
	kernel/sched/sched.c \
	kernel/sched/wait.c \
	lib/time.c

# LAB 5 binaries
KERNEL_BINFILES += \
	user/basicfork \
	user/cowfork \
	user/evilchild \
	user/reaper \
	user/wait \
	user/waitnone \
	user/waitself \
	user/yield

# LAB 6 code
KERNEL_SRCFILES += \
	kernel/boot_ap.S \
	kernel/mp.c \
	kernel/spinlock.c

# LAB 6 binaries
KERNEL_BINFILES += \
	user/mcorefork

# LAB 7 code
KERNEL_SRCFILES += \
	kernel/acpi/mcfg.c \
	kernel/dev/ahci.c \
	kernel/dev/ata.c \
	kernel/dev/disk.c \
	kernel/dev/pci.c

# LAB 7 binaries
KERNEL_BINFILES += \
	user/mempress

# Only build files if they exist.
KERNEL_SRCFILES := $(wildcard $(KERNEL_SRCFILES))

KERNEL_OBJFILES := $(patsubst %.c, $(OBJDIR)/%.o, $(KERNEL_SRCFILES))
KERNEL_OBJFILES := $(patsubst %.S, $(OBJDIR)/%.o, $(KERNEL_OBJFILES))
KERNEL_OBJFILES := $(patsubst $(OBJDIR)/lib/%, $(OBJDIR)/kernel/%, $(KERNEL_OBJFILES))

-include $(KERNEL_OBJFILES:.o=.d)

KERNEL_BINFILES := $(patsubst %, $(OBJDIR)/%, $(KERNEL_BINFILES))

# How to build kernel object files
$(OBJDIR)/kernel/%.o: kernel/%.c $(OBJDIR)/.vars.KERNEL_CFLAGS
	@echo + cc $<
	@mkdir -p $(@D)
	$(V)$(CC) -nostdinc $(KERNEL_CFLAGS) -c -o $@ $< -MT $@ -MMD -MP -MF $(@:.o=.d)

$(OBJDIR)/kernel/%.o: kernel/%.S $(OBJDIR)/.vars.KERNEL_CFLAGS
	@echo + as $<
	@mkdir -p $(@D)
	$(V)$(CC) -nostdinc $(KERNEL_CFLAGS) -c -o $@ $< -MT $@ -MMD -MP -MF $(@:.o=.d)

$(OBJDIR)/kernel/%.o: lib/%.c $(OBJDIR)/.vars.KERNEL_CFLAGS
	@echo + cc $<
	@mkdir -p $(@D)
	$(V)$(CC) -nostdinc $(KERNEL_CFLAGS) -c -o $@ $< -MT $@ -MMD -MP -MF $(@:.o=.d)

# Special flags for kernel/init
$(OBJDIR)/kernel/main.o: override KERNEL_CFLAGS+=$(INIT_CFLAGS)
$(OBJDIR)/kernel/main.o: $(OBJDIR)/.vars.INIT_CFLAGS

# How to build the kernel itself
$(OBJDIR)/kernel/kernel: $(KERNEL_OBJFILES) $(KERNEL_BINFILES) kernel/kernel.ld \
	  $(OBJDIR)/.vars.KERNEL_LDFLAGS
	@echo + ld $@
	$(V)$(LD) -o $@ $(KERNEL_LDFLAGS) $(KERNEL_OBJFILES) $(GCC_LIB) $(KERNEL_BINFILES)
	$(V)$(OBJDUMP) -S $@ > $@.asm
	$(V)$(NM) -n $@ > $@.sym

# How to build the kernel disk image
$(OBJDIR)/kernel/kernel.img: $(OBJDIR)/kernel/kernel $(OBJDIR)/boot/boot
	@echo + mk $@
	$(V)truncate -s %512 $(OBJDIR)/boot/boot
	$(V)dd if=$(OBJDIR)/boot/boot of=$(OBJDIR)/kernel/kernel.img~ 2>/dev/null
	$(V)dd if=$(OBJDIR)/kernel/kernel >>$(OBJDIR)/kernel/kernel.img~ 2>/dev/null
	$(V)truncate -s 5M $(OBJDIR)/kernel/kernel.img~
	$(V)mv $(OBJDIR)/kernel/kernel.img~ $(OBJDIR)/kernel/kernel.img

# Build a swap image.
$(OBJDIR)/kernel/swap.img:
	@echo + mk $@
	$(V)echo -n "SWAP" > $(OBJDIR)/kernel/swap.img~
	$(V)truncate -s 128M $(OBJDIR)/kernel/swap.img~
	$(V)mv $(OBJDIR)/kernel/swap.img~ $(OBJDIR)/kernel/swap.img

all: $(OBJDIR)/kernel/kernel.img $(OBJDIR)/kernel/swap.img

grub: $(OBJDIR)/jos-grub

$(OBJDIR)/jos-grub: $(OBJDIR)/kernel/kernel
	@echo + oc $@
	$(V)$(OBJCOPY) --adjust-vma=0x10000000 $^ $@
