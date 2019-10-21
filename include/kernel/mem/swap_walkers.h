#pragma once

struct sector_info * get_swap_sector(struct task * task, void * addr);
int update_table_entries(struct task * taks, uint64_t base, uint64_t end, uint64_t sector);
