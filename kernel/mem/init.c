#include <types.h>
#include <boot.h>
#include <list.h>
#include <paging.h>

#include <x86-64/asm.h>

#include <kernel/mem.h>
#include <kernel/tests.h>

extern struct list page_free_list[];

/* The kernel's initial PML4. */
struct page_table *kernel_pml4;

/* This function sets up the initial PML4 for the kernel. */
int pml4_setup(struct boot_info *boot_info)
{
	struct page_info *page;

	/* Allocate the kernel PML4. */
	page = page_alloc(ALLOC_ZERO);

	if (!page) {
		panic("unable to allocate the PML4!");
	}

	kernel_pml4 = page2kva(page);

	/* Map in the regions used by the kernel from the ELF header passed to
	 * us through the boot info struct.
	 */
	boot_map_kernel(kernel_pml4, boot_info->elf_hdr);

	/* Use the physical memory that 'bootstack' refers to as the kernel
	 * stack. The kernel stack grows down from virtual address KSTACK_TOP.
	 * Map 'bootstack' to [KSTACK_TOP - KSTACK_SIZE, KSTACK_TOP).
	 */
	boot_map_region(kernel_pml4,
	    (void *)(KSTACK_TOP - KSTACK_SIZE),
	    KSTACK_SIZE,
	    (physaddr_t) bootstack,
	    PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC);


  /* Map in the pages from the buddy allocator as RW-. */
  boot_map_region(kernel_pml4,
      (void *)KPAGES,
      npages * sizeof(struct page_info),
          PADDR(pages),
          PAGE_PRESENT | PAGE_WRITE | PAGE_NO_EXEC );


  /* Migrate the struct page_info structs to the newly mapped area using
   * buddy_migrate().
   */

  buddy_migrate();

	return 0;
}

/*
 * Set up a four-level page table:
 * kernel_pml4 is its linear (virtual) address of the root
 *
 * This function only sets up the kernel part of the address space (i.e.
 * addresses >= USER_TOP). The user part of the address space will be set up
 * later.
 *
 * From USER_TOP to USER_LIM, the user is allowed to read but not write.
 * Above USER_LIM, the user cannot read or write.
 */
void mem_init(struct boot_info *boot_info)
{
	struct mmap_entry *entry;
	uintptr_t highest_addr = 0;
	uint32_t cr0;
	size_t i, n;

	/* Align the areas in the memory map. */
	align_boot_info(boot_info);

	/* Set up the page free lists. */
	for (i = 0; i < BUDDY_MAX_ORDER; ++i) {
		list_init(page_free_list + i);
	};

	/* Find the amount of pages to allocate structs for. */
	entry = (struct mmap_entry *)((physaddr_t)boot_info->mmap_addr);

	for (i = 0; i < boot_info->mmap_len; ++i, ++entry) {
		if (entry->type != MMAP_FREE)
			continue;

		highest_addr = entry->addr + entry->len;
	}

	/* Limit the struct page_info array to the first 8 MiB, as the rest is
	 * still not accessible until lab 2.
	 */
	npages = MIN(BOOT_MAP_LIM, highest_addr) / PAGE_SIZE;

	/*
	 * Allocate an array of npages 'struct page_info's and store it in 'pages'.
	 * The kernel uses this array to keep track of physical pages: for each
	 * physical page, there is a corresponding struct page_info in this array.
	 * 'npages' is the number of physical pages in memory.  Your code goes here.
	 */
	pages = boot_alloc(npages * sizeof *pages);

	/*
	 * Now that we've allocated the initial kernel data structures, we set
	 * up the list of free physical pages. Once we've done so, all further
	 * memory management will go through the page_* functions. In particular, we
	 * can now map memory using boot_map_region or page_insert.
	 */
	page_init(boot_info);

	/* We will set up page tables here in lab 2. */

	/* Setup the initial PML4 for the kernel. */
	pml4_setup(boot_info);

	/* Enable the NX-bit. */
	write_msr(MSR_EFER, MSR_EFER_NXE);

	/* Check the kernel PML4. */
	dump_page_tables(kernel_pml4, PAGE_HUGE);
	lab2_check_pml4();

	/* Load the kernel PML4. */
	load_pml4((void *) PADDR(kernel_pml4));

	/* Check the paging functions. */
	lab2_check_paging();
	//panic("at the disco");

	/* Add the rest of the physical memory to the buddy allocator. */
	page_init_ext(boot_info);

	/* Check the buddy allocator. */
	lab2_check_buddy(boot_info);
}

/*
 * Initialize page structure and memory free list. After this is done, NEVER
 * use boot_alloc() again. After this function has been called to set up the
 * memory allocator, ONLY the buddy allocator should be used to allocate and
 * free physical memory.
 */
void page_init(struct boot_info *boot_info)
{
	struct page_info *page;
	struct mmap_entry *entry;
	uintptr_t pa, end;
	size_t i;

	/* Go through the array of struct page_info structs and:
	 *  1) call list_init() to initialize the linked list node.
	 *  2) set the reference count pp_ref to zero.
	 *  3) mark the page as in use by setting pp_free to zero.
	 *  4) set the order pp_order to zero.
	 */
  for (i = 0; i < npages; ++i) {
    /* LAB 1: your code here. */
    page = &pages[i];

    // call list_init() to initialize the linked list node.
    list_init(&page->pp_node);
    // set the reference count pp_ref to zero.
    page->pp_ref = 0;
    // mark the page as in use by setting pp_free to zero.
    page->pp_free = 0;
    // set the order pp_order to zero.
    page->pp_order = 0;
  }

	entry = (struct mmap_entry *)KADDR(boot_info->mmap_addr);
	end = PADDR(boot_alloc(0));

	/* Go through the entries in the memory map:
	 *  1) Ignore the entry if the region is not free memory.
	 *  2) Iterate through the pages in the region.
	 *  3) If the physical address is above BOOT_MAP_LIM, ignore.
	 *  4) Hand the page to the buddy allocator by calling page_free() if
	 *     the page is not reserved.
	 *
	 * What memory is reserved?
	 *  - Address 0 contains the IVT and BIOS data.
	 *  - boot_info->elf_hdr points to the ELF header.
	 *  - Any address in [KERNEL_LMA, end) is part of the kernel.
	 */
  for (i = 0; i < boot_info->mmap_len; ++i, ++entry) {
    /* LAB 1: your code here. */

    // Ignore the entry if the region is not free memory.
    if (entry->type != MMAP_FREE) {
      continue;
    }

    // Iterate through the pages in the region.
    size_t j;
    size_t start = entry->addr / PAGE_SIZE;
    size_t fin = (entry->addr + entry->len) / PAGE_SIZE;

    for (j = start; j < fin; ++j) {
      page = &pages[j];
      physaddr_t physaddr = page2pa(page);

      // Hand the page to the buddy allocator by calling page_free()
      // If the physical address is not above BOOT_MAP_LIM or reserved.
      if (physaddr >= (uintptr_t)(BOOT_MAP_LIM)) {
        continue;
      } else if (physaddr == 0) {
        continue;
      } else if (physaddr == (uintptr_t)boot_info->elf_hdr) {
        continue;//RESERVED (IVT/BIOS , ELF HEADER)
      } else if (physaddr >= KERNEL_LMA && physaddr < end) {
        continue;//RESERVED (KERNEL DATA)
      } else if (physaddr == PAGE_ADDR(PADDR(boot_info))) {
        continue;
      } else if (entry->type != MMAP_FREE) {
        continue;
      } else {
        page_free(page);
      }
    }
  }
}

/* Extend the buddy allocator by initializing the page structure and memory
 * free list for the remaining available memory.
 */
void page_init_ext(struct boot_info *boot_info)
{
	struct page_info *page, *lookup ,*lookup2;
	struct mmap_entry *entry;
	uintptr_t pa, end;
	size_t i;

	entry = (struct mmap_entry *)KADDR(boot_info->mmap_addr);
	end = PADDR(boot_alloc(0));
	cprintf("page_init_ext \n");

	/* Go through the entries in the memory map:
	 *  1) Ignore the entry if the region is not free memory.
	 *  2) Iterate through the pages in the region.
	 *  3) If the physical address is below BOOT_MAP_LIM, ignore.
	 *  4) Hand the page to the buddy allocator by calling page_free().
	 */
	for (i = 0; i < boot_info->mmap_len; ++i, ++entry) {
		/* LAB 2: your code here. */
		if(entry->type != MMAP_FREE) {
			continue;
		}
		if(entry->addr + entry->len < BOOT_MAP_LIM) {
			continue;
		}

		size_t j, start = entry->addr / PAGE_SIZE;
		size_t fin = (entry->addr + entry->len) / PAGE_SIZE;
		if(start < npages) start = npages +1;

		buddy_map_chunk(kernel_pml4, fin);

		cprintf("%d - %d\n", start, fin);
		cprintf("map region : %p => %p\n", KPAGES + (BOOT_MAP_LIM / PAGE_SIZE), (fin -start) * sizeof(*page));
		// memory are for the pages themselves
		boot_map_region(kernel_pml4,
				(void *)KPAGES + (start * sizeof(*page)) ,
				(fin - start) * sizeof(*page),
				(physaddr_t) end,
				(PAGE_PRESENT | PAGE_WRITE));
	
		// memory area that the pages would map to.
		boot_map_region(kernel_pml4,
				(void *)KERNEL_VMA + BOOT_MAP_LIM, 
				(fin - start) * PAGE_SIZE,
				0x0 + BOOT_MAP_LIM,
				(PAGE_PRESENT | PAGE_WRITE ));
		cprintf("map region : %p => %p\n", KERNEL_VMA + BOOT_MAP_LIM, entry->len - BOOT_MAP_LIM);


		dump_page_tables(kernel_pml4, PAGE_HUGE);
		for(j = start ; j < 2400 ; j++) {
			cprintf("page %d\n", j);
			page = &pages[j];
			lookup = page_lookup(kernel_pml4, (void *)page, NULL) ;
			cprintf("doing lookup\n");
			
			if(lookup == NULL) {
				cprintf(" %p null\n", lookup);
			}
			//cprintf("lookup %p\n", lookup);
//			list_init(&page->pp_node);
			// set the reference count pp_ref to zero.
			page->pp_ref = 0;
			// mark the page as in use by setting pp_free to zero.
			page->pp_free = 0;
			// set the order pp_order to zero.
			page->pp_order = 0;

			page_free(page);
		}
		dump_page_tables(kernel_pml4, PAGE_HUGE);
		//TODO boot map_pages
		//TODO buddy_map_chunk
			//TODO ANTONI THEORY TIME
			//We need to assign both memory in page structs here most likely
			//TODO QUESTION : DO WE CALL BOOT_ALLOC ? 
			//We can allocate in the same fashion as in lab1, we calculate how many pages fit in the region
			//npages = entry->eddr = end / PAGE_SIZE
			//boot_alloc(npages * sizeof *pages) 
	}
}

