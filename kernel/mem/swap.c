#include <types.h>
#include <list.h>
#include <spinlock.h>
#include <kernel/mem.h>
#include <kernel/vma.h>
#include <kernel/dev/disk.h>
#include <kernel/sched/task.h>
#include <ata.h>

/* sector counter */
size_t nsector;

#define DISK_SIZE 134217728
#define STRIP_ENTRY(x) ROUNDDOWN(x & ~PAGE_NO_EXEC & ~PAGE_HUGE & ~ PAGE_PRESENT & ~PAGE_WRITE, PAGE_SIZE)


/* we might have to lock the taken and free list for multiprocessing */
struct spinlock free_list_lock;
struct spinlock taken_list_lock;

/* the sector lists */
struct list sector_free_list;
struct list sector_taken_list;

size_t nfree_sectors;

struct find_info {
  uintptr_t va;
  struct page_info *page;
};

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
  for (size_t j = 1; j < total_sector_info; ++j) {
    sector = &sectors[j];

    // Keep the sector id
    sector->sector_id = j * 8;
    list_init(&sector->swap_node);

    // Make free entry lookup cheap
    spin_lock(&free_list_lock);
    list_insert_after(&sector_free_list, &sector->sector_node);
    spin_unlock(&free_list_lock);
  }

  nfree_sectors = total_sector_info;
}

int swap_free_sectors() {
  return nfree_sectors;
}

static int do_find_pte(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker * walker) {
  struct find_info * info = walker->udata;
  struct page_info *page = pa2page((physaddr_t) STRIP_ENTRY(*entry));

  if(page2pa(page) == page2pa(info->page)) {
    info->va = base; /* is this correct? pls help kaan */
  }

  return 0;
}

static struct task * find_owner(struct page_info * page, struct vma ** vma_f) {
  struct task * task;
  struct list * node, *pagenode;
  struct vma * vma;
  struct page_info * pagef;

  for(pid_t pid = 1 ; pid < (1<<16) ; pid++) { /* loop over all pids except pid 0 */
    task = pid2task(pid, 0); /* acquire task */

    if(!task) continue; /* continue if task doesnt exist */

    list_foreach(&task->task_mmap, node) {
      vma = container_of(node, struct vma, vm_mmap);
      list_foreach(&vma->allocated_pages, pagenode) {
        pagef = container_of(pagenode, struct page_info, pp_node);
        if(pagef == page) {
          *vma_f = vma;
          return task;
        }
      }
    }
  }

  return NULL;
}

/* swap a page out by moving its contents to swap and freeing the page */
int swap_out(struct page_info * page) {
  /* first lets find the owning task , assume its just 1 for now */
  struct task * task = NULL;
  struct vma * vma = NULL;

  task = find_owner(page, &vma);

  if (!task || !vma) return -1;

/* do a pagetable walk to find the va of the page */
  struct find_info info = {
      .va = 0,
      .page = page,
  };

  struct page_walker walker = {
      .get_pte = do_find_pte,
      .udata = &info,
  };

  walk_page_range(task->task_pml4, vma->vm_base, vma->vm_end, &walker);

  if (info.va == 0) return -1;

  spin_lock(&free_list_lock);
  /* first we shall acquire a free sector */
  if(list_is_empty(&sector_free_list)) {
    spin_unlock(&free_list_lock);
    panic("Out of smap memory space\n");
  }

  list_remove(&page->pp_node);
  list_remove(&vma->page_node);

  struct list * free_node = list_pop_left(&sector_free_list);
  struct sector_info * sector = container_of(free_node, struct sector_info, sector_node);
  spin_unlock(&free_list_lock);

  /* now we write the data to disk */
  sector->placeholder = (uintptr_t) info.va; /* preferably write vma address here or something */
  disk_write(disks[SWAP_DISK_NUM], (void *) page2kva(page),
      PAGE_SIZE / SECTOR_SIZE, sector->sector_id);

  int poll_res = 0;
  do {
    poll_res = disk_poll(disks[SWAP_DISK_NUM]);
  } while (!poll_res);

  int res = disk_write(disks[SWAP_DISK_NUM], (void *) page2kva(page),
                       PAGE_SIZE / SECTOR_SIZE, sector->sector_id);

  unmap_page_range(task->task_pml4, (void *) info.va, PAGE_SIZE);
  update_table_entries(task, info.va, info.va + PAGE_SIZE, sector->sector_id,
      page->pp_order == BUDDY_2M_PAGE);

  list_insert_after(&vma->swap_list, &sector->swap_node);

  tlb_invalidate(task->task_pml4, (void *) info.va);

  return 0;
}

/* swap a page in by allocating a page and moving the swap contents to it */
int swap_in(struct task * task, struct sector_info * sector, struct vma * vma) {
  //return 0(or return offset?) on succes, -1 on failure
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

  list_remove(&sector->sector_node);
  list_remove(&sector->swap_node);

  /* read page from disk */
  page = page_alloc(ALLOC_ZERO);

  disk_read(disks[SWAP_DISK_NUM], (void *)page2kva(page),
      PAGE_SIZE / SECTOR_SIZE, sector->sector_id);

  int poll_res = 0;
  do {
    poll_res = disk_poll(disks[SWAP_DISK_NUM]);
  } while (!poll_res);

  int written = disk_read(disks[SWAP_DISK_NUM], (void *)page2kva(page),
            PAGE_SIZE / SECTOR_SIZE, sector->sector_id);

  uint64_t flags = 0;
  if(vma->vm_flags & VM_READ) flags |= PAGE_PRESENT;
  if(vma->vm_flags & VM_WRITE) flags |= PAGE_WRITE;
  if(!(vma->vm_flags & VM_EXEC)) flags |= PAGE_NO_EXEC;
  flags |= PAGE_USER;

  page_insert(task->task_pml4, page, (void *) sector->placeholder, flags);

  /* add sector to free list */
  spin_lock(&free_list_lock);
  list_insert_after(&page->vma_list, &vma->page_node);
  add_fifo(&page->lru_node);
  list_insert_after(&vma->allocated_pages, &page->pp_node);
  list_insert_after(&sector_free_list, &sector->sector_node);
  spin_unlock(&free_list_lock);

  return 0;
}