#include <types.h>
#include <list.h>
#include <spinlock.h>
#include <kernel/mem.h>
#include <kernel/vma.h>
#include <kernel/dev/disk.h>

/* sector counter */
size_t nsector;

#define DISK_SIZE 134217728

/* we might have to lock the taken and free list for multiprocessing */
struct spinlock free_list_lock;
struct spinlock taken_list_lock;

/* the sector lists */
struct list sector_free_list;
struct list sector_taken_list;

struct spinlock sector_free_lock;
struct spinlock sector_taken_lock;

size_t nfree_sectors;

/* memory that stores the sector_info structs */
struct sector_info * sectors;

/* init lists and nsector */
void swap_init() {
  struct page_info * page;

  list_init(&sector_free_list);
  list_init(&sector_taken_list);

  size_t total_sectors = DISK_SIZE / SECTOR_SIZE;
  nsector = total_sectors;
  size_t total_sector_info = (total_sectors / (PAGE_SIZE / SECTOR_SIZE));
  size_t total_page_count = (total_sector_info * sizeof(struct sector_info)) / PAGE_SIZE;

  // Start sector struct after pages structs
  sectors = (struct sector_info *) (pages + npages);

  for (size_t i = 0; i < total_page_count; ++i) {
    page = page_alloc(ALLOC_ZERO);
    page_insert(kernel_pml4, page,
                (void *)sectors + (i * PAGE_SIZE),
                PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC);
  }

  struct sector_info * sector;
  for (size_t j = 0; j < total_sector_info; ++j) {
    sector = &sectors[j];

    // Keep the sector id
    sector->sector_id = j * 8;

    // Make free entry lookup cheap
    list_insert_after(&sector_free_list, &sector->sector_node);
  }

  nfree_sectors = total_sector_info;
}

int swap_free_sectors() {
  return nfree_sectors;
}

/* swap a page out by moving its contents to swap and freeing the page */
int swap_out(struct task * task, void * addr) { //return 0 on succes, -1 on failure
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

  struct vma * found = task_find_vma(task, addr);

  // This process shouldn't have that page
  if (!found) return -1;

  spin_lock(&free_list_lock);

  /* first we shall acquire a free sector */
  if(list_is_empty(&sector_free_list)) {
    spin_unlock(&free_list_lock);
    panic("Out of smap memory space\n");
  } 

  struct list * free_node = list_pop_left(&sector_free_list);
  struct sector_info * sector = container_of(free_node, struct sector_info, sector_node);
  spin_unlock(&free_list_lock);

  /* now we write the data to disk */
  sector->placeholder = (uintptr_t) found->vm_base;
  disk_write(disks[SWAP_DISK_NUM], (void *) found->vm_base,
      PAGE_SIZE / SECTOR_SIZE, sector->sector_id);
  unmap_page_range(task->task_pml4, found->vm_base, found->vm_end - found->vm_base);

  /* insert sector into taken list */
  spin_lock(&taken_list_lock);
  list_insert_after(&sector_taken_list, &sector->sector_node);
  spin_unlock(&taken_list_lock);

  return 0;
}

/* swap a page in by allocating a page and moving the swap contents to it */
int swap_in(struct task * task, struct sector_info * sector, uint64_t flags) { //return 0(or return offset?) on succes, -1 on failure
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
  struct list * node;
  struct page_info * page;


  cprintf("[swap] look up sector id : %d\n", sector->sector_id);
  /* look up sector */
  spin_lock(&taken_list_lock);
  /* clean up sector from taken list */
  if(!sector) return -1;
  list_remove(&sector->sector_node);
  spin_unlock(&taken_list_lock);

  /* read page from disk */
  page = page_alloc(ALLOC_ZERO);
  disk_read(disks[SWAP_DISK_NUM], (void *)page2kva(page), PAGE_SIZE / SECTOR_SIZE, sector->sector_id * PAGE_SIZE); 
  page_insert(task->task_pml4, page, (void *) sector->placeholder, flags);

  /* add sector to free list */
  spin_lock(&free_list_lock);
  list_push_left(&sector_free_list, &sector->sector_node);
  spin_unlock(&free_list_lock);

  return 0;
}

struct sector_info * get_swap_sector(void * addr) {
  struct list *node, *next;
  struct sector_info * sector;

  spin_lock(&free_list_lock);
  list_foreach_safe(&sector_free_list, node, next) {
    sector = container_of(node, struct sector_info, sector_node);
    if (sector->placeholder == (uintptr_t) addr) {
      spin_unlock(&free_list_lock);
      return sector;
    }
  }
  spin_unlock(&free_list_lock);
  return NULL;
}
