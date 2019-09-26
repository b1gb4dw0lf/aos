#include <types.h>
#include <paging.h>

#include <kernel/mem.h>
#define STRIP_ENTRY(x) ROUNDDOWN(x & ~PAGE_NO_EXEC & ~PAGE_HUGE & ~ PAGE_PRESENT & ~PAGE_WRITE, PAGE_SIZE)

struct remove_info {
	struct page_table *pml4;
};

/* Removes the page if present by decrement the reference count, clearing the
 * PTE and invalidating the TLB.
 */
static int remove_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
  struct remove_info *info = walker->udata;

  struct page_info *page = pa2page((physaddr_t) STRIP_ENTRY(*entry));

	//If page is present
	if((*entry & PAGE_PRESENT) && !(*entry & PAGE_DIRTY)) {

    //decrement reference count
    *entry = (physaddr_t) 0x0;
		page_decref(page);
	}

	return 0;
}

/* Removes the page if present and if it is a huge page by decrementing the
 * reference count, clearing the PDE and invalidating the TLB.
 */
static int remove_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct remove_info *info = walker->udata;
	struct page_info *page = pa2page((physaddr_t) STRIP_ENTRY(*entry));

  uint64_t flags = 0 ,index = PAGE_TABLE_INDEX(base);

	if (*entry & PAGE_PRESENT) flags |= PAGE_PRESENT;
	if (*entry & PAGE_WRITE) flags |= PAGE_WRITE;
	if (*entry & PAGE_NO_EXEC) flags |= PAGE_NO_EXEC;
	if (*entry & PAGE_USER) flags |= PAGE_USER;


	//check for huge pages and presence
	if((*entry & PAGE_PRESENT) && (*entry & PAGE_HUGE) && index == 0 && !(*entry & PAGE_DIRTY)) {
    assert(page->pp_ref == 1);
    *entry = (physaddr_t) 0x0;
    page_decref(page);
		tlb_invalidate(info->pml4, page2kva(page));
	} else if ((*entry & PAGE_PRESENT) && (*entry & PAGE_HUGE) && index > 0) {
	  *entry = 0x0;
	  // Create a table at current level
	  ptbl_alloc(entry, base, end, walker);
	  // Get the address of that table
	  struct page_table * table = (struct page_table *) KADDR(ROUNDDOWN(*entry, PAGE_SIZE));

	  // Transport pages that form a huge page to one level below
    tlb_invalidate(info->pml4, page2kva(page));
    for (int i = 0; i < 512; ++i, ++page) {
      page->pp_order = 0;
      if (i != 0) page->pp_ref += 1;
      table->entries[i] = ROUNDDOWN(page2pa(page), PAGE_SIZE) | PAGE_PRESENT;
    }
	}

	return 0;
}

/* Unmaps the range of pages from [va, va + size). */
void unmap_page_range(struct page_table *pml4, void *va, size_t size)
{
	/* LAB 2: your code here. */
	struct remove_info info = {
		.pml4 = pml4,
	};
	struct page_walker walker = {
		.get_pte = remove_pte,
		.get_pde = remove_pde,
		.unmap_pde = ptbl_free,
		.unmap_pdpte = ptbl_free,
		.unmap_pml4e = ptbl_free,
		.udata = &info,
	};

	walk_page_range(pml4, va, va + size, &walker);
}

/* Unmaps all user pages. */
void unmap_user_pages(struct page_table *pml4)
{
	unmap_page_range(pml4, 0, USER_LIM);
}

/* Unmaps the physical page at the virtual address va. */
void page_remove(struct page_table *pml4, void *va)
{
	unmap_page_range(pml4, va, PAGE_SIZE);
}

