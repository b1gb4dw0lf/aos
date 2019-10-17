#include <types.h>
#include <list.h>
#include <spinlock.h>
#include <kernel/mem.h>

/* sector counter */
size_t nsector; 

/* the sector lists */
struct list sector_free_list;
struct list sector_taken_list;

/* init lists and nsector */
void swap_init() {
  list_init(&sector_free_list);
  list_init(&sector_taken_list);;

  nsector = 0;
}

/* swap a page out by moving its contents to swap and freeing the page */
int swap_out(struct page_info *pp) { //return 0 on succes, -1 on failure 
  /* steps below
   * 1 - Request swapping page (acquire lock, move to sector_taken list)
   * 2 - Write page contents to swap
   * 3 - Acquire page descriptor
   *   3.1 - descriptor defines offset in reverse mapping structure
   *   3.2 - write descriptor to swap_sector struct (maybe we should store flags too)
   * 4 - from rmap we acquire all mapping vmas
   * 5 - write swap_offset(swap location) | page-not-present to all relevant PTE's
   * 6 - free the page.
   */

  panic("swap_out not implemented yet!\n");
  return -1;
}

/* swap a page in by allocating a page and moving the swap contents to it */
int swap_in(uint64_t descriptor) { //return 0(or return offset?) on succes, -1 on failure
  /* steps below
   * 1 - page_alloc to request a new page 
   * 2 - write data from swap to the given page, save the location offset
   *   2.1 use offset from PTE entry to find swap location
   *   2.2 lock the swap sector
   * 3 - Look up all mapping vmas in reverse mapping structure using descriptor
   *   3.1 - descriptor defines the offset in reverse mapping structure
   *   3.2 - descriptor is saved in swap_sector struct
   * 4 - write new page location to all relevant PTE's (restore flags?)
   * 5 - move the swap_sector from sector_taken_list to the sector_free_list
   */

  panic("swap_out not implemented yet!\n");
  return -1;
}
