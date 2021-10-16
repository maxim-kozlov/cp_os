#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>

#include "syscall_hooks.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kozlov M.A.");
MODULE_DESCRIPTION("Kernel monitoring");
MODULE_VERSION("0.1");

/* Адрес таблицы системных вызовов */
static unsigned long * __sys_call_table;

#define KERNEL_MONITOR "[KERNEL_MONITOR]: "

syscall_t orig_mkdir;
asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    // 
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    /* Copy the directory name from userspace (pathname, from
     * the pt_regs struct, to kernelspace (dir_name) so that we
     * can print it out to the kernel buffer */
    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO KERNEL_MONITOR "Trying to create directory with name: %s\n", dir_name);

    /* Pass the pt_regs struct along to the original sys_mkdir syscall */
    error = orig_mkdir(regs);
    return error;
}

syscall_t orig_open;
asmlinkage int hook_open(const struct pt_regs *regs)
{
    const char __user *filename = (char *)regs->di;
    int flags = (int)regs->si;
    umode_t mode = (umode_t)regs->dx;

    char kernel_filename[NAME_MAX] = {0};

    long error = strncpy_from_user(kernel_filename, filename, NAME_MAX);

    int fd = orig_open(regs);
        
    if (error > 0)
        printk(KERN_INFO KERNEL_MONITOR "Process %d; open: %s, flags: %x; mode: %x; fd: \n", current->pid, kernel_filename, flags, mode, fd);

    return fd;
}
syscall_t orig_close;
syscall_t orig_read;
syscall_t orig_write;

/* Module initialization function */
static int __init kernel_monitor_init(void)
{
    /* Grab the syscall table, and make sure we succeeded */
    __sys_call_table = kallsyms_lookup_name("sys_call_table");

    /* Grab the function pointer to the real sys_mkdir syscall */
    orig_mkdir  = (syscall_t)__sys_call_table[__NR_mkdir];
    
    orig_open   = (syscall_t)__sys_call_table[__NR_open];
    orig_close  = (syscall_t)__sys_call_table[__NR_close];
    orig_read   = (syscall_t)__sys_call_table[__NR_read];
    orig_write  = (syscall_t)__sys_call_table[__NR_write];

    printk(KERN_INFO KERNEL_MONITOR "Loading ...");
    printk(KERN_DEBUG KERNEL_MONITOR "Found the syscall table at 0x%lx\n", __sys_call_table);
    printk(KERN_DEBUG KERNEL_MONITOR "mkdir: 0x%lx\n", orig_mkdir);
    printk(KERN_DEBUG KERNEL_MONITOR "open:  0x%lx\n", orig_open);
    printk(KERN_DEBUG KERNEL_MONITOR "close: 0x%lx\n", orig_close);
    printk(KERN_DEBUG KERNEL_MONITOR "read:  0x%lx\n", orig_read);
    printk(KERN_DEBUG KERNEL_MONITOR "write: 0x%lx\n", orig_write);

    printk(KERN_INFO KERNEL_MONITOR "Hooking syscalls\n");
    
    /* We are modifying the syscall table, so we need to unset CR0_WP first */
    unprotect_memory();

    __sys_call_table[__NR_mkdir] = (unsigned long)hook_mkdir;
    __sys_call_table[__NR_open] = (unsigned long)hook_open;

    protect_memory();

    return 0;
}

static void __exit kernel_monitor_exit(void)
{
    printk(KERN_INFO KERNEL_MONITOR "Restoring syscalls\n");
    unprotect_memory();
    
    __sys_call_table[__NR_mkdir]    = (unsigned long)orig_mkdir;
    
    __sys_call_table[__NR_open]     = (unsigned long)orig_open;
    __sys_call_table[__NR_close]    = (unsigned long)orig_close;
    __sys_call_table[__NR_read]     = (unsigned long)orig_read;
    __sys_call_table[__NR_write]    = (unsigned long)orig_write;

    protect_memory();
    
    printk(KERN_INFO KERNEL_MONITOR "Unloaded.\n");
}

module_init(kernel_monitor_init);
module_exit(kernel_monitor_exit);