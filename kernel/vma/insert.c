#include <types.h>

#include <kernel/mem.h>
#include <kernel/vma.h>

/* Inserts the given VMA into the red-black tree of the given task. First tries
 * to find a VMA for the end address of the given end address. If there is
 * already a VMA that overlaps, this function returns -1. Then the VMA is
 * inserted into the red-black tree and added to the sorted linked list of
 * VMAs.
 */
int insert_vma(struct task *task, struct vma *vma)
{
	struct rb_node *rb_parent = NULL;
	struct list *node;
	struct vma *found, *parent;
	int dir;

	found = find_vma(&rb_parent, &dir, &task->task_rb, vma->vm_end);

	if (found && found->vm_base < vma->vm_end) {
		return -1;
	}

	parent = rb_parent ? container_of(rb_parent, struct vma, vm_rb) : NULL;
	node = &parent->vm_mmap;

	if (!parent) {
		task->task_rb.root = &vma->vm_rb;
	} else {
		rb_parent->child[dir] = &vma->vm_rb;
		vma->vm_rb.parent = rb_parent;
	}

	if (rb_insert(&task->task_rb, &vma->vm_rb) < 0) {
		return -1;
	}

	if (!parent) {
		list_insert_before(&task->task_mmap, &vma->vm_mmap);
	} else {
		if (dir) {
			list_insert_before(node, &vma->vm_mmap);
		} else { 
			list_insert_after(node, &vma->vm_mmap);
		}
	}

	return 0;
}

/* Allocates and adds a new VMA for the given task.
 *
 * This function first allocates a new VMA. Then it copies over the given
 * information. The VMA is then inserted into the red-black tree and linked
 * list. Finally, this functions attempts to merge the VMA with the adjacent
 * VMAs.
 *
 * Returns the new VMA if it could be added, NULL otherwise.
 */
struct vma *add_executable_vma(struct task *task, char *name, void *addr,
	size_t size, int flags, void *src, size_t len)
{
	/* LAB 4: your code here. */

	// Allocate VMA
	struct vma *new_vma = kmalloc(sizeof(struct vma));

	// Copy given info
	new_vma->vm_flags = flags;
	new_vma->vm_src = src;
	new_vma->vm_len = len;
	new_vma->vm_name = name;
	new_vma->vm_base = ROUNDDOWN(addr, PAGE_SIZE);
	new_vma->vm_end = ROUNDUP(addr + size, PAGE_SIZE);
	new_vma->real_base = addr;
	new_vma->is_shared = 0;
	new_vma->page_addr = NULL;

  rb_node_init(&new_vma->vm_rb);

	// Insert into task rb and task list
	if (insert_vma(task, new_vma) < 0) {
    return NULL;
	}

	merge_vmas(task, new_vma);
	return new_vma;
}

struct vma *add_executable_vma_v2(struct task *task, char *name, void *addr,
                               size_t size, int flags, void *src, size_t len, void * page_addr) {
  struct vma * vma = add_executable_vma(task, name, addr, size, flags, src, len);
  vma->page_addr = page_addr;
  return vma;
}

/* A simplified wrapper to add anonymous VMAs, i.e. VMAs not backed by an
 * executable.
 */
struct vma *add_anonymous_vma(struct task *task, char *name, void *addr,
	size_t size, int flags)
{
	return add_executable_vma(task, name, addr, size, flags, NULL, 0);
}

static int check_consecutive_addresses(struct task * task, void * addr, size_t size) {
  size_t num_of_pages = ROUNDUP(size, PAGE_SIZE) / PAGE_SIZE;
  for (void * next = ROUNDDOWN(addr, PAGE_SIZE) + PAGE_SIZE;
        next < (void *) USER_LIM && num_of_pages > 0; next += PAGE_SIZE, num_of_pages--) {

    if (task_find_vma(task, next) != 0) {
      return 0;
    }

    if (num_of_pages == 0) {
      return 1;
    }
  }

  return 0;
}

static void * do_vma_loop(struct task * task, size_t size, void * start, void * end) {
  size_t num_of_pages = ROUNDUP(size, PAGE_SIZE) / PAGE_SIZE;
  size_t found_consecutive_pages = 0;
  void * base = NULL;

  for (void * next = start;
       end < next && next < (void *) USER_LIM ; next -= PAGE_SIZE) {
    // If vma addr exists in task continue
    // Also set base to null to avoid mapping non consecutive addresses
    if (task_find_vma(task, next) != 0) {
      found_consecutive_pages = 0;
      base = NULL;
      continue;
    }

    found_consecutive_pages++;
    // Since we are searching from end to beginning
    base = next;

    if ((found_consecutive_pages == num_of_pages) && base) {
      return base;
    }
  }

  return base;
}

/* Allocates and adds a new VMA to the requested address or tries to find a
 * suitable free space that is sufficiently large to host the new VMA. If the
 * address is NULL, this function scans the address space from the end to the
 * beginning for such a space. If an address is given, this function scans the
 * address space from the given address to the beginning and then scans from
 * the end to the given address for such a space.
 *
 * Returns the VMA if it could be added. NULL otherwise.
 */
struct vma *add_vma(struct task *task, char *name, void *addr, size_t size,
	int flags)
{
  void * base = NULL;
  if (!addr) {
    // Address is null. Now, find a suitable address by scanning the address space

    base = do_vma_loop(task, size, (void *) USER_LIM - 5 * PAGE_SIZE, 0);
    return add_anonymous_vma(task, name, base, size, flags);

  } else if (addr && (task_find_vma(task, addr) != 0)
              && !check_consecutive_addresses(task, addr, size)) {
    // VMA at that address already exists or the size does not fit

    // Search from addr towards the beginning
    base = do_vma_loop(task, size, ROUNDDOWN(addr, PAGE_SIZE), 0);

    // If not found search for addr starting from end to addr
    if (!base) {
      base = do_vma_loop(task, ROUNDUP(size, PAGE_SIZE),
          (void *) USER_LIM - PAGE_SIZE, ROUNDDOWN(addr, PAGE_SIZE));
    }

    return base;

  }else if (addr) {
    // VMA at that address does not exist so just insert it to the address
    return add_anonymous_vma(task, name, addr, size, flags);
  }

	/* LAB 4: your code here. */
	return NULL;
}

