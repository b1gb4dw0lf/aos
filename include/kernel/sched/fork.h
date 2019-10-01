#pragma once

#include <task.h>

pid_t sys_fork(void);
int sys_exec(const char * binary);

