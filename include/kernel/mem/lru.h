#pragma once

struct list working_set;
struct spinlock working_set_lock;

struct list inactive_set;
struct spinlock inactive_set_lock;

void lru_init();
void insert_after_working(struct list * node);
void remove_working(struct list * node);
void insert_after_inactive(struct list * node);
void remove_inactive(struct list * node);
void kswap(struct list * active);
void add_fifo(struct list * node);
struct list * get_fifo();
