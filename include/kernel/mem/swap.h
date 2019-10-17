#pragma once

#define MAX_SECTORS (128 * 1024 * 1024) / 512 //disksize / sector size
#define SWAP_DISK_NUM 1 //swap.img disknumber for the disks variable

struct list swaplist_taken;
struct list swaplist_free;

struct swap_sector_info {
	struct spinlock lock;	  /* cluster typically 512 byte size.
                           * per-cluster lock
                           * descriptor can be used to retrieve mapping vma's
                  				 */
	uint64_t descriptor;
};
