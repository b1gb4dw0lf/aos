#pragma once

#include <types.h>
#include <paging.h>

int dump_page_tables(struct page_table *pml4, uint64_t mask);
int dump_page_tables_range(struct page_table *pml4, void * base, void * end, uint64_t mask);


