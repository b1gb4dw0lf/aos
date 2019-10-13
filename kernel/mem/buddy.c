#include <types.h>
#include <list.h>
#include <paging.h>
#include <spinlock.h>
#include <string.h>

#include <kernel/mem.h>

/* Physical page metadata. */
size_t npages;
struct page_info *pages;

/* Lists of physical pages. */
struct list page_free_list[BUDDY_MAX_ORDER];

#ifndef USE_BIG_KERNEL_LOCK
/* Lock for the buddy allocator. */
struct spinlock buddy_lock = {
#ifdef DEBUG_SPINLOCK
	.name = "buddy_lock",
#endif
};
#endif

/* Counts the number of free pages for the given order.
 */
size_t count_free_pages(size_t order)
{
	struct list *node;
	size_t nfree_pages = 0;

	if (order >= BUDDY_MAX_ORDER) {
		return 0;
	}

	list_foreach(page_free_list + order, node) {
		++nfree_pages;
	}

	return nfree_pages;
}

/* Shows the number of free pages in the buddy allocator as well as the amount
 * of free memory in kiB.
 *
 * Use this function to diagnose your buddy allocator.
 */
void show_buddy_info(void)
{
	struct page_info *page;
	struct list *node;
	size_t order;
	size_t nfree_pages;
	size_t nfree = 0;

	cprintf("Buddy allocator:\n");

	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		nfree_pages = count_free_pages(order);

		cprintf("  order #%u pages=%u\n", order, nfree_pages);

		nfree += nfree_pages * (1 << (order + 12));
	}

	cprintf("  free: %u kiB\n", nfree / 1024);
}

/* Gets the total amount of free pages. */
size_t count_total_free_pages(void)
{
	struct page_info *page;
	struct list *node;
	size_t order;
	size_t nfree_pages;
	size_t nfree = 0;

	for (order = 0; order < BUDDY_MAX_ORDER; ++order) {
		nfree_pages = count_free_pages(order);
		nfree += nfree_pages * (order + 1);
	}

	return nfree;
}

/* Splits lhs into free pages until the order of the page is the requested
 * order req_order.
 *
 * The algorithm to split pages is as follows:
 *  - Given the page of order k, locate the page and its buddy at order k - 1.
 *  - Decrement the order of both the page and its buddy.
 *  - Mark the buddy page as free and add it to the free list.
 *  - Repeat until the page is of the requested order.
 *
 * Returns a page of the requested order.
 */
 struct page_info *buddy_split(struct page_info *lhs, size_t req_order)
{
  struct page_info *rhs;
  uint8_t order = lhs->pp_order;
  uintptr_t buddy_address;
  size_t scale, page_index, buddy_index;
  list_remove(&lhs->pp_node);

  while(order > req_order && order > 0) {
    order--;

    scale = (size_t) 1 << order; // pagen

    // Get the page index
    page_index = PAGE_INDEX(page2pa(lhs));
    // Get the buddy at order k-1
    buddy_index = page_index + scale;
    buddy_address = buddy_index * PAGE_SIZE;
    rhs = pa2page(buddy_address);

    // Set the order of both to k-1
    lhs->pp_order = order;
    rhs->pp_order = order;
    rhs->pp_free = 1;

    //Add rhs to free list
    list_insert_after(page_free_list + rhs->pp_order, &rhs->pp_node);
  }

  return lhs;
}

/* Merges the buddy of the page with the page if the buddy is free to form
 * larger and larger free pages until either the maximum order is reached or
 * no free buddy is found.
 *
 * The algorithm to merge pages is as follows:
 *  - Given the page of order k, locate the page with the lowest address
 *    and its buddy of order k.
 *  - Check if both the page and the buddy are free and whether the order
 *    matches.
 *  - Remove the page and its buddy from the free list.
 *  - Increment the order of the page.
 *  - Repeat until the maximum order has been reached or until the buddy is not
 *    free.
 *
 * Returns the largest merged free page possible.
 */
struct page_info *buddy_merge(struct page_info *page)
{
  uintptr_t page_address, buddy_index, page_index, buddy_address;
  struct page_info *buddy = NULL;

  assert(page->pp_ref == 0);

  // Continue if max order is not reached
  if(page->pp_order < (BUDDY_MAX_ORDER - 1)) {
    size_t scale = (size_t) 1 << (page->pp_order);
    page_address = page2pa(page);
    page_index = PAGE_INDEX(page_address);

    // Determine if the page is on the left or right
    if((page_index / scale) % 2 == 0) {
      buddy_index = page_index + scale;
    } else {
      buddy_index = page_index - scale;
    }

    buddy_address = buddy_index * PAGE_SIZE;
    // TODO This part might be problematic
    // Return if buddy is out of bounds?
    if(PAGE_INDEX(buddy_address) >= npages) {
      return page;
    }

    buddy = pa2page(buddy_address);
    if(buddy->pp_order == page->pp_order && buddy->pp_free && page->pp_free) {
      list_remove(&buddy->pp_node);
      list_remove(&page->pp_node);

      // Call recursively with the left page
      if(page_index < buddy_index) {
        page->pp_order = page->pp_order + 1;
        buddy->pp_free = 0;
        return buddy_merge(page);
      } else {
        buddy->pp_order = buddy->pp_order + 1;
        page->pp_free = 0;
        return buddy_merge(buddy);
      }
    }
  }

  return page;
}

/* Given the order req_order, attempts to find a page of that order or a larger
 * order in the free list. In case the order of the free page is larger than the
 * requested order, the page is split down to the requested order using
 * buddy_split().
 *
 * Returns a page of the requested order or NULL if no such page can be found.
 */
struct page_info *buddy_find(size_t req_order)
{
  struct list *node;
  struct page_info *res;
  struct page_info *page;

  for(size_t order = req_order; order < BUDDY_MAX_ORDER; order++) {
    list_foreach(page_free_list + order, node) {
      page = container_of(node, struct page_info, pp_node);

      if(page->pp_free && order == req_order) {
        // Found a free page with the requested order
        return page;
      } else if (order > req_order && page->pp_free){
        // We found a free page with a greater order so we need to split
        page = buddy_split(page, req_order);
        return page;
      }
    }
  }

#ifndef USE_BIG_KERNEL_LOCK
  spin_unlock(&buddy_lock);
#endif
  //this means no requested order page could be find, so we're going to icnr
  return NULL;
}

/*
 * Allocates a physical page.
 *
 * if (alloc_flags & ALLOC_ZERO), fills the entire returned physical page with
 * '\0' bytes.
 * if (alloc_flags & ALLOC_HUGE), returns a huge physical 2M page.
 *
 * Beware: this function does NOT increment the reference count of the page -
 * this is the caller's responsibility.
 *
 * Returns NULL if out of free memory.
 *
 * Hint: use buddy_find() to find a free page of the right order.
 * Hint: use page2kva() and memset() to clear the page.
 */
struct page_info *page_alloc(int alloc_flags)
{
#ifndef USE_BIG_KERNEL_LOCK
  if (!holding(&buddy_lock)) {
    spin_lock(&buddy_lock);
  }
#endif
  struct page_info *page = alloc_flags & ALLOC_HUGE ?
                           buddy_find(BUDDY_2M_PAGE) :
                           buddy_find(BUDDY_4K_PAGE);

  if (page == NULL) {
    return NULL;
  }

  // Make sure there is no use after free
#ifdef BONUS_LAB1
  assert(page->pp_ref == 0);
#endif

  page->pp_free = 0;
  list_remove(&page->pp_node);
  if(list_is_empty(page_free_list + page->pp_order)) {
    list_init(page_free_list + page->pp_order);
  }

  if (alloc_flags & ALLOC_ZERO) {
    uint64_t page_size = (1<<page->pp_order) * PAGE_SIZE;
    memset(page2kva(page), 0, page_size);
  }

#ifndef USE_BIG_KERNEL_LOCK
  spin_unlock(&buddy_lock);
#endif
  return page;
}

/*
 * Return a page to the free list.
 * (This function should only be called when pp->pp_ref reaches 0.)
 *
 * Hint: mark the page as free and use buddy_merge() to merge the free page
 * with its buddies before returning the page to the free list.
 */
void page_free(struct page_info *pp)
{
  struct page_info *res;

  // Make sure the page has no refs
  assert(pp->pp_ref == 0);
  // Make sure the page is not out of bounds
//  assert(PAGE_INDEX(page2pa(pp)) >= 0 && PAGE_INDEX(page2pa(pp)) <= npages);

#ifdef BONUS_LAB1
  // Make sure the page won't be freed again
	assert(!pp->pp_free);
	// Make sure the page is aligned
  assert(page2pa(pp) % PAGE_SIZE == 0);
#endif

  list_init(&pp->pp_node);
  pp->pp_free=1; //Mark page as free

  if(pp->pp_order == (BUDDY_MAX_ORDER -1)) {
    list_insert_after(page_free_list + pp->pp_order, &pp->pp_node); //Add node to free list
  } else {
    res = buddy_merge(pp); // Merge page with buddies TODO implement this
    list_insert_after(page_free_list + res->pp_order, &res->pp_node); //Add node to free list
  }
}

/*
 * Decrement the reference count on a page,
 * freeing it if there are no more refs.
 */
void page_decref(struct page_info *pp)
{
#ifndef USE_BIG_KERNEL_LOCK
  spin_lock(&buddy_lock);
#endif
  if (--pp->pp_ref == 0) {
		page_free(pp);
	}
#ifndef USE_BIG_KERNEL_LOCK
  spin_unlock(&buddy_lock);
#endif
}

static int in_page_range(void *p)
{
	return ((uintptr_t)pages <= (uintptr_t)p &&
	        (uintptr_t)p < (uintptr_t)(pages + npages));
}

static void *update_ptr(void *p)
{
	if (!in_page_range(p))
		return p;

	return (void *)((uintptr_t)p + KPAGES - (uintptr_t)pages);
}

void buddy_migrate(void)
{
#ifndef USE_BIG_KERNEL_LOCK
  spin_lock(&buddy_lock);
#endif
  struct page_info *page;
	struct list *node;
	size_t i;

	for (i = 0; i < npages; ++i) {
		page = pages + i;
		node = &page->pp_node;

		node->next = update_ptr(node->next);
		node->prev = update_ptr(node->prev);
	}

	for (i = 0; i < BUDDY_MAX_ORDER; ++i) {
		node = page_free_list + i;

		node->next = update_ptr(node->next);
		node->prev = update_ptr(node->prev);
	}

	pages = (struct page_info *)KPAGES;
#ifndef USE_BIG_KERNEL_LOCK
  spin_unlock(&buddy_lock);
#endif
}

int buddy_map_chunk(struct page_table *pml4, size_t index)
{
#ifndef USE_BIG_KERNEL_LOCK
  spin_lock(&buddy_lock);
#endif

  struct page_info *page, *base;
	void *end;
	size_t nblocks = (1 << (12 + BUDDY_MAX_ORDER - 1)) / PAGE_SIZE;
	size_t nalloc = ROUNDUP(nblocks * sizeof *page, PAGE_SIZE) / PAGE_SIZE;
	size_t i;

	index = ROUNDDOWN(index, nblocks);
	base = pages + index;

	for (i = 0; i < nalloc; ++i) {
	  // This is gonna release the lock
		page = page_alloc(ALLOC_ZERO);
#ifndef USE_BIG_KERNEL_LOCK
    spin_lock(&buddy_lock);
#endif

		if (!page) {
#ifndef USE_BIG_KERNEL_LOCK
      spin_unlock(&buddy_lock);
#endif
			return -1;
		}

		if (page_insert(pml4, page, (char *)base + i * PAGE_SIZE,
		    PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC) < 0) {
#ifndef USE_BIG_KERNEL_LOCK
      spin_unlock(&buddy_lock);
#endif

      return -1;
		}
	}

#ifndef USE_BIG_KERNEL_LOCK
	if (!holding(&buddy_lock)) {
    spin_lock(&buddy_lock);
	}
#endif



  for (i = 0; i < nblocks; ++i) {
		page = base + i;
		list_init(&page->pp_node);
	}

	npages = index + nblocks;

#ifndef USE_BIG_KERNEL_LOCK
  spin_unlock(&buddy_lock);
#endif

  return 0;
}

