#include <types.h>
#include <list.h>
#include <spinlock.h>
#include <kernel/mem.h>
#include <kernel/vma.h>
#include <kernel/dev/disk.h>
#include <kernel/sched/task.h>
#include <ata.h>
#include <syscall.h>
#include <kernel/sched.h>

/* sector counter */
size_t nsector;

extern void kswitch(struct int_frame  *frame);

#define DISK_SIZE 134217728
#define STRIP_ENTRY(x) ROUNDDOWN(x & ~PAGE_NO_EXEC & ~PAGE_HUGE & ~ PAGE_PRESENT & ~PAGE_WRITE, PAGE_SIZE)

/* we might have to lock the taken and free list for multiprocessing */
struct spinlock free_list_lock;
struct spinlock taken_list_lock;
struct spinlock disk_lock;

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
    //set sector va to 0
    sector->pa = 0;

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

static int post_swap_ops(struct task * task, struct vma * vma, struct page_info * page, uint64_t sector) {
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

  uint64_t x,y;
  if(page->va) {
    info.va = page->va;
  } else {

    walk_page_range(task->task_pml4, vma->vm_base, vma->vm_end, &walker);
  }

  if (info.va == 0) return -1;

  page->pp_ref = 0;
  update_table_entries(task, info.va, info.va + PAGE_SIZE, sector);

  tlb_invalidate(task->task_pml4, (void *) info.va);

  return 0;
}

/* swap a page out by moving its contents to swap and freeing the page */
int swap_out(struct page_info * page) {
  /* first lets find the owning task , assume its just 1 for now */
  struct task * task = NULL;
  struct vma * vma = NULL;

  spin_lock(&free_list_lock);
  /* first we shall acquire a free sector */
  if(list_is_empty(&sector_free_list)) {
    spin_unlock(&free_list_lock);
    panic("Out of smap memory space\n");
  }

  list_remove(&page->pp_node);

  struct list * free_node = list_pop_left(&sector_free_list);
  struct sector_info * sector = container_of(free_node, struct sector_info, sector_node);
  spin_unlock(&free_list_lock);

  sector->vma = page->vma;
  sector->ref_count = page->pp_ref;
  sector->pa = 0;

  void * page_addr = page2kva(page);

  if (!page->vma->owner) {
    // It is shared, unmap from all tasks
    struct list * node;

    list_foreach(&page->vma->vma_list, node) {
      vma = container_of(node, struct vma, vma_node);
      task = pid2task(vma->owner, 0);
      spin_lock(&task->task_lock);
      post_swap_ops(task, vma, page, sector->sector_id);
      spin_unlock(&task->task_lock);
    }

  } else {
    task = pid2task(page->vma->owner, 0);
    spin_lock(&task->task_lock);
    vma = page->vma;
    post_swap_ops(task, vma, page, sector->sector_id);
    spin_unlock(&task->task_lock);
  }

  while(holding(&disk_lock)) {
    sched_yield();
  }

  spin_lock(&disk_lock);

  disk_write(disks[SWAP_DISK_NUM], page_addr,
             PAGE_SIZE / SECTOR_SIZE, sector->sector_id);

  while (!disk_poll(disks[SWAP_DISK_NUM])) {
    kswitch(&this_cpu->cpu_task->task_frame);
  }

  int res = disk_write(disks[SWAP_DISK_NUM], page_addr,
                       PAGE_SIZE / SECTOR_SIZE, sector->sector_id);

  if (res < 0) {
    panic("Disk Write Problems\n");
  }

  spin_unlock(&disk_lock);

  page_free(page);

  return 0;
}

/* swap a page in by allocating a page and moving the swap contents to it */
int swap_in(struct task * task, void * addr, struct sector_info * sector, struct vma * vma) {
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
  struct page_info * page;

  while(holding(&disk_lock)) {
    sched_yield();
  }

  if (sector->ref_count == 1) {
    sector->ref_count--;
    list_remove(&sector->sector_node);
  } else {
    sector->ref_count--;
  }

  /* read page from disk */
  if(sector->pa == 0) { 
    page = page_alloc(ALLOC_ZERO);
    page->pp_ref = sector->ref_count + 1; /* + 1 since we decrement the ref count above */
    sector->pa = page2pa(page);

    spin_lock(&disk_lock);

    disk_read(disks[SWAP_DISK_NUM], (void *)page2kva(page),
        PAGE_SIZE / SECTOR_SIZE, sector->sector_id);

    int poll_res = 0;
    do {
      poll_res = disk_poll(disks[SWAP_DISK_NUM]);
    } while (!poll_res);

    int written = disk_read(disks[SWAP_DISK_NUM], (void *)page2kva(page),
              PAGE_SIZE / SECTOR_SIZE, sector->sector_id);

    spin_unlock(&disk_lock);
  } else {
    page = pa2page(sector->pa);
  }

  uint64_t flags = 0;
  if(vma->vm_flags & VM_READ) flags |= PAGE_PRESENT;
  if(vma->owner != 0) {
    if(vma->vm_flags & VM_WRITE )  flags |= PAGE_WRITE; /* COW shouldnt have write */
  }
  if(!(vma->vm_flags & VM_EXEC)) flags |= PAGE_NO_EXEC;
  flags |= PAGE_USER;

  // It is shared no longer cow
  // TODO: How to keep cow?
  if (!sector->vma->owner) {
    struct list * node;
    struct vma * sub_vma = NULL;
    list_foreach(&page->vma->vma_list, node) {
      sub_vma = container_of(node, struct vma, vma_node);
      if (task->task_pid == sub_vma->owner) {
        break;
      }
    }
    page->vma = sub_vma;
  } else {
    page->vma = sector->vma;
  }

  page_insert(task->task_pml4, page, addr, flags);
  page->pp_ref--; /* insert increases pp_ref by 1, we  undo this since we try to keep original pp_ref */

  /* we could re-use the disk space though but then we would need to give  it a new sector_info struct */

  /* add sector to free list */
  if(sector->ref_count == 0) {
    add_fifo(&page->lru_node);
    spin_lock(&free_list_lock);
    list_insert_after(&sector_free_list, &sector->sector_node);
    spin_unlock(&free_list_lock);
  }

  return 0;
}

int should_exit = 0;
void kthread_swap() {
  struct list * node;
  struct page_info * page;

  // Run until there is no swappable memory
  while (!list_is_empty(&working_set)) {
    if (get_free_page_count() < 5000 && !list_is_empty(&working_set)) {
      for (int i = 0; i < 512; ++i) {
        node = pop_fifo();

        if (!node) break;


        page = container_of(node, struct page_info, lru_node);
        swap_out(page);
      }
    } else {
      kswitch(&cur_task->task_frame);
    }
  }

  syscall(SYS_kill, 0, 0, 0, 0, 0, 0);
}
