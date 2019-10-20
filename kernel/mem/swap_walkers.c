#include <types.h>
#include <kernel/mem.h>

extern struct sector_info * sectors;
struct sector_find {
  uint64_t va;
  uint64_t sector;
  uint8_t isHuge;
};

static int update_sector_pte(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker * walker) {
  struct sector_find * info = walker->udata;

  if (base == info->va) {
    *entry = info->sector << 9;
  }

  return 0;
}

static int update_sector_pde(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker * walker) {
  struct sector_find * info = walker->udata;

  // If it is not a huge table and no table then allocate one
  if (!*entry && !info->isHuge) {
    ptbl_alloc(entry, base, end, walker);
  } else if (!*entry && base == info->va) {
    // If no entry and its huge then update this
    *entry = info->sector << 9;
  }

  return 0;
}


int update_table_entries(struct task * taks, uint64_t base, uint64_t end, uint64_t sector, uint8_t isHuge) {
  struct sector_find info;
  info.sector = sector;
  info.va = base;
  info.isHuge = isHuge;

  struct page_walker walker = {
      .get_pte = update_sector_pte,
      .get_pde = update_sector_pde,
      .get_pdpte = ptbl_alloc,
      .get_pml4e = ptbl_alloc,
      .udata = &info,
  };

  return walk_page_range(taks->task_pml4, (void *) base, (void *) end, &walker);
}

static int get_sector_pte(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker * walker) {
  struct sector_find * info = walker->udata;

  if (base == info->va) {
    info->sector = *entry;
  }

  return 0;
}

static int get_sector_pde(physaddr_t *entry, uintptr_t base, uintptr_t end, struct page_walker * walker) {
  struct sector_find * info = walker->udata;

  // If it is a huge page this will be sent
  // Otherwise, it will be overwritten in pte
  if (!(*entry & PAGE_PRESENT) && base == info->va) {
    info->sector = *entry;
  }

  return 0;
}

struct sector_info * get_swap_sector(struct task * task, void * addr) {
  struct sector_find info;
  info.va = (uint64_t) addr;
  info.sector = 0;

  struct page_walker walker = {
      .get_pte = get_sector_pte,
      .get_pde = get_sector_pde,
      .udata = &info,
  };

  if (walk_page_range(task->task_pml4, addr, addr+PAGE_SIZE, &walker) < 0) {
    return NULL;
  }

  if (info.sector == 0) return NULL;

  cprintf("Sector is: %d\n", info.sector >> 9);

  size_t index = (info.sector >> 9) / 8;
  return &sectors[index];
}

