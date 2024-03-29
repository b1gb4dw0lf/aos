#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

#define STRIP_ENTRY(x) ROUNDDOWN(x & ~PAGE_NO_EXEC & ~PAGE_HUGE & ~ PAGE_PRESENT & ~PAGE_WRITE, PAGE_SIZE)

struct protect_info {
	struct page_table *pml4;
	uint64_t flags;
	uintptr_t base, end;
};

/* Changes the protection of the page. Avoid calling tlb_invalidate() if
 * nothing changes at all.
 */
static int protect_pte(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct protect_info *info = walker->udata;

	//ANTONI notes
	//so the theory is that *entry has some flags which we gotta clear, and then we give it some new damn flags. 
	//if the flags are equal we try to avoid invalidating
	//END ANTONI notes
	struct page_info *page = pa2page(STRIP_ENTRY(*entry));
	
	if((STRIP_ENTRY(*entry) | info->flags) == *entry) {
		return 0;
	} else {
		*entry = STRIP_ENTRY(*entry) | info->flags;// remove flags by rounding down to page size? 
		tlb_invalidate(info->pml4, page2kva(page));
	}
	/* LAB 3: your code here. */
	return 0;
}

/* Changes the protection of the huge page, if the page is a huge page and if
 * the range covers the full huge page. Otherwise if the page is a huge page,
 * but if the range does not span an entire huge page, this function calls
 * ptbl_split() to split up the huge page. Avoid calling tlb_invalidate() if
 * nothing changes at all.
 */
static int protect_pde(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	struct protect_info *info = walker->udata;
	if(*entry & PAGE_HUGE) { 
		if (end - base < (( 1 << BUDDY_2M_PAGE) * PAGE_SIZE) -PAGE_SIZE) {
			return ptbl_split(entry, base, end, walker);
		} else if((STRIP_ENTRY(*entry) | info->flags) == *entry) {
			return 0;
		} else {
			*entry = (STRIP_ENTRY(*entry) | info->flags);// remove flags by rounding down to page size? 
			*entry = *entry | PAGE_HUGE;
			tlb_invalidate(info->pml4, page2kva(pa2page(STRIP_ENTRY(*entry))));
			return 0;
		}
	} else {
		return 0;
	}
	/* LAB 3: your code here. */
	return 0;
}

/* Changes the protection of the region [va, va + size) to the permissions
 * specified by flags.
 */
void protect_region(struct page_table *pml4, void *va, size_t size,
    uint64_t flags)
{
	/* LAB 3: your code here. */
	struct protect_info info = {
		.pml4 = pml4,
		.flags = flags,
		.base = ROUNDDOWN((uintptr_t)va, PAGE_SIZE),
		.end = ROUNDUP((uintptr_t)va + size, PAGE_SIZE) - 1,
	};
	struct page_walker walker = {
		.get_pte = protect_pte,
		.get_pde = protect_pde,
		.udata = &info,
	};

	walk_page_range(pml4, va, (void *)((uintptr_t)va + size), &walker);
}

