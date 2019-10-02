#include <types.h>
#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/mem.h>
#include <kernel/sched.h>
#include <kernel/vma.h>

#include <lib.h>

int sys_mquery(struct vma_info *info, void *addr)
{
	struct vma *vma;
	struct list *node;
	physaddr_t *entry;

	/* Check if the user has read/write access to the info struct. */
	assert_user_mem(cur_task, info, sizeof *info, PAGE_USER | PAGE_WRITE);

	/* Do not leak information about the kernel space. */
	if (addr >= (void *)USER_LIM) {
		return -1;
	}

	/* Clear the info struct. */
	memset(info, 0, sizeof *info);

	/* Find the VMA with an end address that is greater than the requested
	 * address, but also the closest to the requested address.
	 */
	vma = find_vma(NULL, NULL, &cur_task->task_rb, addr);

	if (!vma) {
		/* If there is no such VMA, it means the address is greater
		 * than the address of any VMA in the address space, i.e. the
		 * user is requesting the free gap at the end of the address
		 * space. The base address of this free gap is the end address
		 * of the highest VMA and the end address is simply USER_LIM.
		 */
		node = list_tail(&cur_task->task_mmap);

		info->vm_end = (void *)USER_LIM;

		if (!node) {
			return 0;
		}

		vma = container_of(node, struct vma, vm_mmap);
		info->vm_base = vma->vm_end;

		return 0;
	}

	if (addr < vma->vm_base) {
		/* The address lies outside the found VMA. This means the user
		 * is requesting the free gap between two VMAs. The base
		 * address of the free gap is the end address of the previous
		 * VMA. The end address of the free gap is the base address of
		 * the VMA that we found.
		 */
		node = list_prev(&cur_task->task_mmap, &vma->vm_mmap);

		info->vm_end = vma->vm_base;

		if (!node) {
			return 0;
		}

		vma = container_of(node, struct vma, vm_mmap);
		info->vm_base = vma->vm_end;

		return 0;
	}

	/* The requested address actually lies within a VMA. Copy the
	 * information.
	 */
	strncpy(info->vm_name, vma->vm_name, 64);
	info->vm_base = vma->vm_base;
	info->vm_end = vma->vm_end;
	info->vm_prot = vma->vm_flags;
	info->vm_type = vma->vm_src ? VMA_EXECUTABLE : VMA_ANONYMOUS;

	/* Check if the address is backed by a physical page. */
	if (page_lookup(cur_task->task_pml4, addr, &entry)) {
		info->vm_mapped = (*entry & PAGE_HUGE) ? VM_2M_PAGE : VM_4K_PAGE;
	}

	return 0;
}

void *sys_mmap(void *addr, size_t len, int prot, int flags, int fd,
	uintptr_t offset)
{
	/* LAB 4: your code here. */

	cprintf("MMAP - addr: %p size: %d\n", addr, len);

	int valid_flags = 0;

	if (addr && (addr >= (void*)USER_LIM || (addr + len) >= (void*)USER_LIM)) return MAP_FAILED;

	// Do ugly sanity checks. Shh, I know.
	if (flags & MAP_POPULATE) {
	  valid_flags |= MAP_POPULATE;
	  flags ^= MAP_POPULATE;
	}
	if (flags & MAP_PRIVATE) {
	  valid_flags |= MAP_PRIVATE;
	  flags ^= MAP_PRIVATE;
	}
  if (flags & MAP_FIXED) {
    valid_flags |= MAP_FIXED;
    flags ^= MAP_FIXED;
  }
	if (flags & MAP_ANONYMOUS) {
	  valid_flags |= MAP_ANONYMOUS;
	  flags ^= MAP_ANONYMOUS;
	}

	if (flags > 0) return MAP_FAILED;
	if (!addr && (valid_flags) & MAP_FIXED) return MAP_FAILED;

	// More ugly checks, just scroll down.
	int vma_flags = 0;
	if (prot & PROT_READ) vma_flags |= VM_READ;
	if (prot & PROT_EXEC) vma_flags |= VM_EXEC;
	if (prot & PROT_WRITE) vma_flags |= VM_WRITE;

	// Should X fail when there is no R?
	if (((prot & PROT_WRITE) || (prot & PROT_EXEC)) && !(prot & PROT_READ)) return MAP_FAILED;
	if ((prot & PROT_WRITE) && (prot & PROT_EXEC)) return MAP_FAILED;

	struct vma * vma = NULL;

	if ((valid_flags & MAP_ANONYMOUS) || (fd == -1)) {
	  cprintf("Calling add_vma\n");

	  if (valid_flags & MAP_FIXED) {
	    cprintf("Trying to remove previous mapping\n");
	    vma = task_find_vma(cur_task, addr);
	    cprintf("Found? %c\n", vma ? 'Y' : 'N');
	    if (vma) {
	      remove_vma_range(cur_task, vma->vm_base, vma->vm_end - vma->vm_base);
	    }
	  }

	  vma = add_vma(cur_task, "user", addr, len, vma_flags);
	} else {
	  panic("Files not supported yet.");
	}

	if (!vma) return MAP_FAILED;

	if (valid_flags & MAP_POPULATE) {
	  populate_vma_range(cur_task, vma->vm_base, vma->vm_end - vma->vm_base, vma->vm_flags);
	}

	cprintf("Returning %p %p\n", vma, vma->vm_base);

	return vma->vm_base;
}

void sys_munmap(void *addr, size_t len)
{
	/* check if area can even be mapped.. */
	if (addr >= (void*)USER_LIM) return ; 
	/* if range exceeds USER_LIM, change range to [addr, user_LIM] */
	if ((addr + len) >= (void *)USER_LIM) return;
	unmap_vma_range(cur_task, addr, len);
	/* LAB 4: your code here. */
}

int sys_mprotect(void *addr, size_t len, int prot)
{
  // If not a valid pointer
  if (!addr) return -1;

  // If tries to access beyond user lim
	if (addr >= (void*)USER_LIM) return -1;

	// if range exceeds USER_LIM
	if ((addr + len) >= (void *)USER_LIM) return -1;

  // Addr needs to be page aligned
  if (!page_aligned((uintptr_t)addr)) return -1;

  // W^X protection
  if ((prot & PROT_EXEC) && (prot & PROT_WRITE)) return -1;

  return protect_vma_range(cur_task, addr, len, prot);
}

int sys_madvise(void *addr, size_t len, int advise)
{
	/* LAB 4 (bonus): your code here. */
	if (!addr) return -1;
	if (len <= 0) return -1;
	if (addr >= (void *)USER_LIM) return -1;
	if(advise & MADV_WILLNEED) {
		populate_region(cur_task->task_pml4, addr, len, (PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC | PAGE_USER));
		return 0;
	}
	if(advise & MADV_DONTNEED) {
		unmap_page_range(cur_task->task_pml4, addr, len);
		return 0;
	}
	return -ENOSYS;
}

