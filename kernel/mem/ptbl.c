#include <types.h>
#include <string.h>
#include <paging.h>

#include <kernel/mem.h>

#define STRIP_ENTRY(x) ROUNDDOWN(x & ~PAGE_NO_EXEC & ~PAGE_HUGE & ~ PAGE_PRESENT & ~PAGE_WRITE, PAGE_SIZE)

/* Allocates a page table if none is present for the given entry.
 * If there is already something present in the PTE, then this function simply
 * returns. Otherwise, this function allocates a page using page_alloc(),
 * increments the reference count and stores the newly allocated page table
 * with the PAGE_PRESENT | PAGE_WRITE | PAGE_USER permissions.
 */
int ptbl_alloc(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{

  if (!(*entry & PAGE_PRESENT)) {
    struct page_info * page = page_alloc(ALLOC_ZERO);
    page->pp_ref += 1;
    assert(page_aligned(page2pa(page)));
    *entry = page2pa(page) | PAGE_PRESENT | PAGE_WRITE | PAGE_USER;
  }

	return 0;
}

/* Splits up a huge page by allocating a new page table and setting up the huge
 * page into smaller pages that consecutively make up the huge page.
 *
 * If no huge page was mapped at the entry, simply allocate a page table.
 *
 * Otherwise if a huge page is present, allocate a new page, increment the
 * reference count and have the PDE point to the newly allocated page. This
 * page is used as the page table. Then allocate a normal page for each entry,
 * copy over the data from the huge page and set each PDE.
 *
 * Hint: the only user of this function is boot_map_region(). Otherwise the 2M
 * physical page has to be split down into its individual 4K pages by updating
 * the respective struct page_info structs.
 *
 * Hint: this function calls ptbl_alloc(), page_alloc(), page2pa() and
 * page2kva().
 */
int ptbl_split(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{
	/* LAB 2: your code here. */
  if (!(*entry & PAGE_PRESENT) || (*entry & PAGE_HUGE)) return 0;
  //struct boot_map_info *info = walker->udata;
  uint64_t index = PAGE_TABLE_INDEX(base);
  struct page_info *page = pa2page(*entry);
  //no huge page mapped, allocate a ptlb
  if (!(*entry & PAGE_HUGE)) {
    ptbl_alloc(entry, base, end, walker);
  } else {
    struct page_info *newpage = page_alloc(ALLOC_ZERO);
    newpage->pp_ref += 1;
    *entry = page2pa(newpage) | PAGE_PRESENT | PAGE_WRITE; 
    struct page_table * ptbl = (struct page_table *) ROUNDDOWN(*entry, PAGE_SIZE);
    for(int i = 0 ; i < 512; ++i) {
      newpage = page_alloc(ALLOC_ZERO);
      newpage->pp_ref += 1;
      ptbl->entries[i] = ROUNDDOWN(page2pa(newpage), PAGE_SIZE) | PAGE_PRESENT | PAGE_USER;
    }
  }
	return 0;
}

/* Attempts to merge all consecutive pages in a page table into a huge page.
 *
 * First checks if the PDE points to a huge page. If the PDE points to a huge
 * page there is nothing to do. Otherwise the PDE points to a page table.
 * Then this function checks all entries in the page table to check if they
 * point to present pages and share the same flags. If not all pages are
 * present or if not all flags are the same, this function simply returns.
 * At this point the pages can be merged into a huge page. This function now
 * allocates a huge page and copies over the data from the consecutive pages
 * over to the huge page.
 * Finally, it sets the PDE to point to the huge page with the flags shared
 * between the previous pages.
 *
 * Hint: don't forget to free the page table and the previously used pages.
 */
int ptbl_merge(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{

  if (!(*entry & PAGE_PRESENT) || (*entry & PAGE_HUGE)) return 0;

  // Get the table if this is not a huge page
  struct page_table * table = (struct page_table *) KADDR(STRIP_ENTRY(*entry));
  physaddr_t *entry1, *entry2;
  // Get the flags of first entry
  uint64_t flags = 0;
  uint64_t entry_flags = 0;

  if (table->entries[0] & PAGE_PRESENT) flags |= PAGE_PRESENT;
  if (table->entries[0] & PAGE_WRITE) flags |= PAGE_WRITE;
  if (table->entries[0] & PAGE_NO_EXEC) flags |= PAGE_NO_EXEC;
  if (table->entries[0] & PAGE_USER) flags |= PAGE_USER;

  // Check if all entries in the table are present and have same flags
  for (int i = 0; i < 512; ++i) {
    if (!table->entries[i] ||
      (table->entries[i] & PAGE_PRESENT && pa2page(STRIP_ENTRY(table->entries[i]))->pp_ref == 0)
      || (table->entries[i] & PAGE_PRESENT && pa2page(STRIP_ENTRY(table->entries[i]))->pp_ref > 1)
      || !(table->entries[i] & PAGE_PRESENT)) {
      return 0;
    }

    if (table->entries[i] & PAGE_PRESENT) entry_flags |= PAGE_PRESENT;
    if (table->entries[i] & PAGE_WRITE) entry_flags |= PAGE_WRITE;
    if (table->entries[i] & PAGE_NO_EXEC) entry_flags |= PAGE_NO_EXEC;
    if (table->entries[i] & PAGE_USER) entry_flags |= PAGE_USER;

    if (flags != entry_flags) return 0;
  }


  // Allocate a huge page
  struct page_info * new_page = page_alloc(ALLOC_HUGE);

  if (!new_page) {
    return 0;
  }

  cprintf("merging entry %p, *entry %p,  base %p, end %p\n", entry, *entry, base, end);

  // Increase the ref
  new_page->pp_ref += 1;

  physaddr_t old_entry = STRIP_ENTRY(*entry);
  struct page_info * old_page = pa2page(old_entry);

  physaddr_t entry_to_be_merged;
  for (int j = 0; j < 512; ++j) {
    uintptr_t * addr = (void *)KADDR(STRIP_ENTRY(table->entries[j]));
    memcpy(page2kva(new_page) + (j * PAGE_SIZE), addr, PAGE_SIZE);
    entry_to_be_merged = STRIP_ENTRY(table->entries[j]);
    assert(pa2page(entry_to_be_merged)->pp_ref == 1);
    page_decref(pa2page(entry_to_be_merged));
  }

  assert(old_page->pp_ref == 1);
  page_decref(old_page);

  *entry = page2pa(new_page) | PAGE_PRESENT | PAGE_HUGE | flags;
  return 0;
}

/* Frees up the page table by checking if all entries are clear. Returns if no
 * page table is present. Otherwise this function checks every entry in the
 * page table and frees the page table if no entry is set.
 *
 * Hint: this function calls pa2page(), page2kva() and page_free().
 */
int ptbl_free(physaddr_t *entry, uintptr_t base, uintptr_t end,
    struct page_walker *walker)
{

  if (*entry & PAGE_PRESENT) {
    struct page_info * page = pa2page(STRIP_ENTRY(*entry));
    struct page_table * table = (struct page_table *) page2kva(page);

    // If there is a entry return without freeing the table
    for (int i = 0; i < 512; ++i) {
      if (table->entries[i]) return 0;
    }
    // If the loop is passed there is no entry in the table free the page
    assert(page->pp_ref == 1);
    page_decref(page);
    *entry = 0x0;
  }

	return 0;
}
