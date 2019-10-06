#include <types.h>
#include <cpu.h>

#include <kernel/acpi.h>
#include <kernel/mem.h>

/* Sets up slab allocators for every multiple of SLAB_ALIGN bytes starting from
 * SLAB_ALIGN.
 */
int kmem_init(void)
{
	struct slab *slab;
	size_t obj_size;
	size_t i;

	for (i = 0; i < nslabs; ++i) {
		slab = slabs + i;
		obj_size = (i + 1) * SLAB_ALIGN;
		slab_setup(slab, obj_size);
	}

	return 0;
}

int kmem_init_mp(void)
{
	/* assume first cpu is already setup? */
	struct slab *slab;
	size_t obj_size;
	size_t i;
	struct cpuinfo cpu;
	struct kmem_cache cache;

	/* loop through all cpus to assign kmem cache */
	for (int i = 0 ; i < NCPUS ; ++i) {
		/* get cpuinfo struct */
		cpu = cpus[i];
		/* go through the per-cpu slab allocator */
		cache = cpu.kmem;
		/* allocate all slabs */
		for(int j = 0; j < cache._nslabs; ++j) {
			slab = cache._slabs + j;
			obj_size = (i + 1) * SLAB_ALIGN;
			slab_setup(slab, obj_size);
		}
	}
	/* LAB 6: your code here. */
	return 0;
}

/* Allocates a chunk of memory of size bytes.
 *
 * If the size is zero, this function returns NULL.
 * If the size is greater than or equal to the highest object size available in
 * the set of slab allocators, this function returns NULL.
 * Otherwise this function finds the best fit slab allocator for the requested
 * size and uses slab_alloc() to allocate the chunk of memory. */
void *kmalloc(size_t size)
{
	/* Should deal with per-cpu structs */
	struct kmem_cache cache = this_cpu->kmem;
	size_t index;

	if (size == 0) {
		return NULL;
	}

	size = ROUNDUP(size, SLAB_ALIGN);
	index = (size / SLAB_ALIGN) - 1;

	if (index >= cache._nslabs) {
		return NULL;
	}

	return slab_alloc(cache._slabs + index);
}

/* This function calls slab_free() to free the chunk of memory. */
void kfree(void *p)
{
	slab_free(p);
}
