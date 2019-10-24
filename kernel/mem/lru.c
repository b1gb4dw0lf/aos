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

void add_clock(struct list * node) {
  spin_lock(&working_set_lock);
  list_insert_after(&working_set, node);
  spin_unlock(&working_set_lock);
}

struct list * pop_clock() {
  struct list * node, * next;
  struct page_info * page;
  spin_lock(&working_set_lock);

  // If all are 0 for the first round
  for (int i = 0; i < 2; ++i) {
    list_foreach_safe(&working_set, node, next) {
      page = container_of(node, struct page_info, lru_node);
      if (page->R == 0) {
        list_remove(&working_set);
        list_insert_before(node, &working_set);
        list_remove(node);
        spin_unlock(&working_set_lock);
        return node;
      } else {
        page->R = 0;
      }
    }
  }

  node = list_pop_left(&working_set);
  spin_unlock(&working_set_lock);
  return node;
}
