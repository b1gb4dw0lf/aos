#pragma once

#include <list.h>
#include <rbtree.h>

/* The VMA flags */
#define VM_READ  (1 << 0)
#define VM_WRITE (1 << 1)
#define VM_EXEC  (1 << 2)
#define VM_DIRTY (1 << 4)

/* A Virtual Memory Area (VMA) describes a virtual memory area in the virtual
 * address space of a task.
 */
struct vma {
	/* A human-readable name to describe the VMA. */
	char *vm_name;
	struct rb_node vm_rb;

	/* The linked list anchor in the sorted list of VMAs. */
	struct list vm_mmap;

	/* The range this area covers. */
	void *vm_base, *vm_end;

	/* If the VMA is not anonymous, a pointer to the data that backs it up.
	 * This is used by executables.
	 */
	void *vm_src;

	/* The amount of data available to back up the VMA. */
	size_t vm_len;

	/* The permission flags of the VMA. */
	int vm_flags;

	// Saves the real starting offset of the file
	void *real_base;

	// Used to determine if to be mapped area is shared
	int is_shared;

	void * page_addr;

	struct list swap_list;

	struct list page_node;
	struct list vma_list;
	struct list vma_node;

	pid_t owner;
};

