#pragma once

#include <kernel/vma.h>

#define MAX_SECTORS (128 * 1024 * 1024) / 512 //disksize / sector size
#define MAX_PAGES (128 * 1024 * 1024) / 4096
#define SWAP_DISK_NUM 1 //swap.img disknumber for the disks variable
#define SECTOR_SIZE 512

struct sector_info {
	//struct spinlock lock;	  
	 /* cluster typically 512 byte size.
                           * per-cluster lock
                           * descriptor can be used to retrieve mapping vma's
                  				 */
	uint64_t sector_id;

  // This has nothing to do with identification of shared pages
  // This will be decremented if it is shared and not removed from swap entry
  // Until other processes map this too
	uint16_t ref_count;

  // If shared points to anon vma that has a list of owning vmas
	struct vma * vma;

	// For maintaining a free sector list
	struct list sector_node;
};

void swap_init(void);
int swap_out(struct page_info * page);
int swap_in(struct task * task, void * addr, struct sector_info * sector, struct vma * vma);
int swap_free_sectors(void);
