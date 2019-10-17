#pragma once

#define MAX_SECTORS (128 * 1024 * 1024) / 512 //disksize / sector size
#define SWAP_DISK_NUM 1 //swap.img disknumber for the disks variable
#define SECTOR_SIZE 512

struct sector_info {
	struct spinlock lock;	  /* cluster typically 512 byte size.
                           * per-cluster lock
                           * descriptor can be used to retrieve mapping vma's
                  				 */
	uint64_t descriptor;
	struct list sector_node;
};

void swap_init(void);
int swap_out(struct page_info *pp);
int swap_in(uint64_t descriptor);
