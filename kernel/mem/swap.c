#include <types.h>
#include <list.h>
#include <spinlock.h>
#include <kernel/mem.h>
#include <kernel/dev/disk.h>

/* sector counter */
size_t nsector; 

/* we might have to lock the taken and free list for multiprocessing */

/* the sector lists */
struct list sector_free_list;
struct list sector_taken_list;

/* memory that stores the sector_info structs */

/* init lists and nsector */
void swap_init() {
  uint64_t sector_counter;
  uint64_t page_counter;
  struct page_info * page;
  list_init(&sector_free_list);
  list_init(&sector_taken_list);

  /* for efficient storing we calculate the requires space dynamically */
  uint64_t sector_info_pagecount = (MAX_PAGES * sizeof(struct sector_info)) / PAGE_SIZE;
  uint64_t sector_info_per_page = PAGE_SIZE / sizeof(struct sector_info);

  for(page_counter = 0 ; page_counter < sector_info_pagecount ; page_counter++) {
    /* allocate a page for the sector_info structs */
    page = page_alloc(ALLOC_ZERO);
    for(sector_counter = 0 ; sector_counter < sector_info_per_page ; sector_counter++) {
      struct sector_info * sector = (void*)page2pa(page) + (sector_counter * sizeof(struct sector_info));
      sector->sector_id = (page_counter * sector_info_per_page) + sector_counter;
      list_push(&sector_free_list, &sector->sector_node);
    }
  }
  nsector = 0;
}

int swap_free_sectors() {
  struct list *node;
  size_t nfree_sectors = 0;

  list_foreach(&sector_free_list, node) {
    ++nfree_sectors;
  }

  return nfree_sectors;
}

/* swap a page out by moving its contents to swap and freeing the page */
int swap_out(struct page_info *pp) { //return 0 on succes, -1 on failure 
  /* steps below
   * 1 - Request swapping page (acquire lock, move to sector_taken list)
   * 2 - Write page contents to swap
   * 3 - Acquire page descriptor [ or we do lookups in all pts]
   *   3.1 - descriptor defines offset in reverse mapping structure 
   *   3.2 - write descriptor to swap_sector struct (maybe we should store flags too)
   * 4 - from rmap we acquire all mapping vmas
   * 5 - write swap_offset(swap location) | page-not-present to all relevant PTE's
   * 6 - free the page.
   */

  /* first we shall acquire a free sector */
  if(list_is_empty(&sector_free_list)) {
    panic("Out of smap memory space\n");
  } 

  struct sector_info * sector = container_of(list_pop_left(&sector_free_list), struct sector_info, sector_node);
  /* [?]now we acquire the lock */
  /* now we write the data to disk */
  for(int s = 0 ; s < PAGE_SIZE ; s += SECTOR_SIZE) {
    /* SWAP_DISK_NUM describes disk id 1, so disks[1] should be swap */
    /* page2pa(pp) + s should increase by 512 bytes each iteration */
    /* sector_id is initialized by swap_init and describes PAGE_SIZE offsets on disk */
    disk_write(disks[SWAP_DISK_NUM], (void *)page2pa(pp) + s, SECTOR_SIZE, sector->sector_id * PAGE_SIZE); 
  }

  /* [?]now we unlock */



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
   * 3 - Look up all mapping vmas in reverse mapping structure using descriptor [ or do lookups ]
   *   3.1 - descriptor defines the offset in reverse mapping structure
   *   3.2 - descriptor is saved in swap_sector struct
   * 4 - write new page location to all relevant PTE's (restore flags?)
   * 5 - move the swap_sector from sector_taken_list to the sector_free_list
   */
  cprintf("sizeof sector struct : %d\n", sizeof(struct sector_info));

  panic("swap_out not implemented yet!\n");
  return -1;
}
