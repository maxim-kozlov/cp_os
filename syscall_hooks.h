#ifndef HOOKS_H
#define HOOKS_H
#include <linux/syscalls.h>

/******* Hooks *******/

/* См. https://syscalls64.paolostivanin.com/ для получения информации о переданных аргументах через регистры. */
typedef asmlinkage long (*syscall_t)(const struct pt_regs *);

/******* Helpers *******/

/* 16ый бит в регистре cr0 - это бит W(rite) P(rotection), 
 * который определяет, можно ли писать в read-only страницы. */
#define CR0_WP 0x00010000

/* Встроенная в linux функция write_cr0() не позволяет изменять бит WP,
 * поэтому реализуем свою функцию */
extern unsigned long __force_order;
inline void cr0_write(unsigned long cr0)
{
    // mov cr0, rax
    asm volatile("mov %0, %%cr0" : "+r"(cr0), "+m"(__force_order));
}

static inline void protect_memory(void)
{
    unsigned long cr0 = read_cr0();
    cr0_write(cr0 | CR0_WP);
}

static inline void unprotect_memory(void)
{
    unsigned long cr0 = read_cr0();
    cr0_write(cr0 & ~CR0_WP);
}

#endif // HOOKS_H