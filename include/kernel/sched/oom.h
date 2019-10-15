#pragma once
#include <kernel/vma.h>

size_t get_mm_rss(struct task * task);
struct task * get_task_to_kill();
