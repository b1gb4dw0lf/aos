#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

struct populate_info {
	uint64_t flags;
	uintptr_t base, end;
};

static int populate_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct page_info *page = page_alloc(ALLOC_ZERO);
	struct populate_info *info = walker->udata;

	page->pp_ref += 1;//FIXME needed?
	physaddr_t newAddr = page2pa(page) | info->flags | PAGE_PRESENT;
	*entry = newAddr;

	/* LAB 3: your code here. */
	return 0;
}

static int populate_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct page_info *page;
	struct populate_info *info = walker->udata;

	if(end - base >= (( 1 << BUDDY_2M_PAGE ) * PAGE_SIZE) - 1) {
		page = page_alloc(ALLOC_HUGE | ALLOC_ZERO);
		page->pp_ref += 1;
		assert(page->pp_ref == 1);
		physaddr_t newAddr = page2pa(page) | info->flags | PAGE_PRESENT | PAGE_HUGE;
		*entry = newAddr;
	} else {
		ptbl_alloc(entry, base, end, walker);
	}
	/* LAB 3: your code here. */
	return 0;
}

/* Populates the region [va, va + size) with pages by allocating pages from the
 * frame allocator and mapping them.
 */
void populate_region(struct page_table *pml4, void *va, size_t size,
	uint64_t flags)
{
	/* LAB 3: your code here. */
	struct populate_info info = {
		.flags = flags,
		.base = ROUNDDOWN((uintptr_t)va, PAGE_SIZE),
		.end = ROUNDUP((uintptr_t)va + size, PAGE_SIZE) - 1,
	};
	struct page_walker walker = {
		.get_pte = populate_pte,
		.get_pde = populate_pde,
		.get_pdpte = ptbl_alloc,
		.get_pml4e = ptbl_alloc,
		.udata = &info,
	};

	walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);
}

