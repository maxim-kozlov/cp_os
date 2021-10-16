#ifndef HOOKS_H
#define HOOKS_H
#include <linux/syscalls.h>

/******* Hooks *******/

/* See https://syscalls64.paolostivanin.com/ for information about passed arguments via registers */
typedef asmlinkage long (*syscall_t)(const struct pt_regs *);

/******* Helpers *******/

/* Bit 16 in the cr0 register is the W(rite) P(rotection) bit, which
 * determines whether read-only pages can be written to. */
#define CR0_WP 0x00010000

/* The built in linux write_cr0() function stops us from modifying
 * the WP bit, so we write our own instead */
extern unsigned long __force_order;
inline void cr0_write(unsigned long cr0)
{
    asm volatile("mov %0,%%cr0" : "+r"(cr0), "+m"(__force_order));
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