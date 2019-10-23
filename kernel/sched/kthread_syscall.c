/* System call stubs. */

#include <syscall.h>
#include <lib.h>

extern int64_t do_ksyscall(uint64_t num, uint64_t a1, uint64_t a2,
                          uint64_t a3, uint64_t a4, uint64_t a5, uint64_t a6);

static inline unsigned long ksyscall(int num, int check,
                                    unsigned long a1, unsigned long a2, unsigned long a3, unsigned long a4,
                                    unsigned long a5, unsigned long a6)
{
  unsigned long ret;

  /*
   * Generic system call: pass system call number in AX,
   * up to five parameters in DX, CX, BX, DI, SI.
   * Interrupt kernel with T_SYSCALL.
   *
   * The "volatile" tells the assembler not to optimize
   * this instruction away just because we don't use the
   * return value.
   *
   * The last clause tells the assembler that this can
   * potentially change the condition codes and arbitrary
   * memory locations.
   */
  ret = do_ksyscall(num, a1, a2, a3, a4, a5, a6);

  if(check && ret < 0) {
    panic("syscall %d returned %d (> 0)", num, ret);
  }

  return ret;
}
int kkill(pid_t pid)
{
  return ksyscall(SYS_kill, 1, pid, 0, 0, 0, 0, 0);
}

void ksched_yield(void)
{
  ksyscall(SYS_yield, 0, 0, 0, 0, 0, 0, 0);
}
