#include <types.h>
#include <paging.h>

#include <kernel/mem.h>

void lru_init() {
  list_init(&working_set);
  list_init(&inactive_set);
}

void insert_after_working(struct list * node) {
  spin_lock(&working_set_lock);
  list_insert_after(&working_set, node);
  spin_unlock(&working_set_lock);
}

void remove_working(struct list * node) {
  spin_lock(&working_set_lock);
  list_remove(node);
  spin_unlock(&working_set_lock);
}

void insert_after_inactive(struct list * node) {
  spin_lock(&inactive_set_lock);
  list_insert_after(&inactive_set, node);
  spin_unlock(&inactive_set_lock);
}

void remove_inactive(struct list * node) {
  spin_lock(&inactive_set_lock);
  list_remove(node);
  spin_unlock(&inactive_set_lock);
}

void kswap(struct list * active) {
  spin_lock(&inactive_set_lock);
  spin_lock(&inactive_set_lock);

  list_remove(active);
  list_insert_after(&inactive_set, active);

  spin_unlock(&inactive_set_lock);
  spin_unlock(&inactive_set_lock);
}

void add_fifo(struct list * node) {
  spin_lock(&working_set_lock);
  list_insert_after(&working_set, node);
  spin_unlock(&working_set_lock);
}

struct list * get_fifo() {
  struct list * node;
  spin_lock(&working_set_lock);
  node = list_pop_left(&working_set);
  spin_unlock(&working_set_lock);
  return node;
}
