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

#include <linux/sched.h>
#include <linux/fdtable.h>
#include <linux/path.h>
#include <linux/dcache.h>

#include <linux/timekeeping32.h>

/*
 * open.c
 */
struct open_flags {
	int open_flag;
	umode_t mode;
	int acc_mode;
	int intent;
	int lookup_flags;
};

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
    const char __user *pathname = (char *)regs->di;
    umode_t mode = (umode_t)regs->si;

    char dir_name[NAME_MAX] = {0};

    /* копировать имя директории из пр-ва пользователя в пр-во ядра */
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
        
    if (!error && current->real_parent->pid > 3)
         printk(KERN_INFO KERNEL_MONITOR "Process %d; open: %s, flags: %x; mode: %x; fd: %d\n", current->pid, kernel_filename, flags, mode, fd);

    return fd;
}

syscall_t orig_close;
asmlinkage int hook_close(const struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->di;

    /* Не логировать закрытие stdin, stdout, stderr */
    if (fd > 2 && current->real_parent->pid > 3)
    {
        /* Open file information: */
        // current->files

        printk(KERN_INFO KERNEL_MONITOR "Process %d; close fd: %d; filename: %s\n", current->pid, fd, 
            current->files->fdt->fd[fd]->f_path.dentry->d_iname);
    }
    return orig_close(regs);
}

syscall_t orig_read;
asmlinkage int hook_read(const struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->di;
    char __user *buf = (char*)regs->si;
    size_t count = (size_t)regs->dx;
    
    /* Не логировать стандартный ввод/вывод, а так же системные процессы */
    if (fd > 2 && current->real_parent->pid > 3)
        printk(KERN_INFO KERNEL_MONITOR "Process %d; read fd: %d; buf: %p; count: %ld; filename: %s;\n", 
            current->pid, fd, buf, count,
            current->files->fdt->fd[fd]->f_path.dentry->d_iname);

    return orig_read(regs);;
}

syscall_t orig_write;
asmlinkage int hook_write(const struct pt_regs *regs)
{
    unsigned int fd = (unsigned int)regs->di;
    const char __user *buf = (const char*)regs->si;
    size_t count = (size_t)regs->dx;

    /* Не логировать стандартный ввод/вывод, а так же системные процессы */
    if (fd > 2 && current->real_parent->pid > 3)
        printk(KERN_INFO KERNEL_MONITOR "Process %d; write fd: %d; buf: %p; count: %ld; filename: %s\n", current->pid, fd, buf, count,
            current->files->fdt->fd[fd]->f_path.dentry->d_iname);
    return orig_write(regs);
}

static asmlinkage struct file* (*orig_do_filp_open)(int dfd, struct filename *pathname, const struct open_flags *op);
static asmlinkage struct file* hook_do_filp_open(int dfd, struct filename *pathname, const struct open_flags *op)
{
    if (current->real_parent->pid > 3)
        printk(KERN_INFO KERNEL_MONITOR "Process %d; open %s;\n", current->pid, pathname->name);

    struct file* file;
    file = orig_do_filp_open(dfd, pathname, op);

    return file;
}

static asmlinkage int (*orig_get_unused_fd_flags)(unsigned flags);
static asmlinkage int hook_get_unused_fd_flags(unsigned flags)
{
    int fd;
    fd = orig_get_unused_fd_flags(flags);

    if (current->real_parent->pid > 3)
        printk(KERN_INFO KERNEL_MONITOR "Process %d; get_unused_fd %d;\n", current->pid, fd);

    return fd;
}

static asmlinkage int (*orig_filp_close)(struct file *filp, fl_owner_t id);
static asmlinkage int hook_filp_close(struct file *filp, fl_owner_t id)
{
    int ret;
    ret = orig_filp_close(filp, id);

    if (current->real_parent->pid > 3)
        printk(KERN_INFO KERNEL_MONITOR "Process %d; filp_close %s; ret: %d\n", current->pid, filp->f_path.dentry->d_iname, ret);

    return ret;
}

static asmlinkage int (*orig_bdev_read_page)(struct block_device *bdev, sector_t sector, struct page *page);
static asmlinkage int hook_bdev_read_page(struct block_device *bdev, sector_t sector, struct page *page)
{
    /* Вызов оригинального bdev_read_page() */
    // On entry, the page should be locked. It will be unlocked when the page has been read. If the block driver implements rw_page synchronously, that will be true on exit from this function, but it need not be.
    // Errors returned by this function are usually “soft”, eg out of memory, or queue full; callers should try a different route to read this page rather than propagate an error back up the stack.
    // bdev -- The device to read the page from
    // sector -- The offset on the device to read the page to (need not be aligned)
    // page -- The page to read
    int err;
    err = orig_bdev_read_page(bdev, sector, page);
    printk(KERN_INFO KERNEL_MONITOR "Process %d bdev_read_page; dev: %d\n", current->pid, bdev->bd_dev);
    return err;
}

static asmlinkage int (*orig_bdev_write_page)(struct block_device *bdev, sector_t sector, struct page *page, struct writeback_control *wbc);
static asmlinkage int hook_bdev_write_page(struct block_device *bdev, sector_t sector, struct page *page, struct writeback_control *wbc)
{
    /* Вызов оригинального bdev_read_page() */
    // On entry, the page should be locked and not currently under writeback. 
    // On exit, if the write started successfully, the page will be unlocked and under writeback. 
    // If the write failed already (eg the driver failed to queue the page to the device), 
    // the page will still be locked. 
    // If the caller is a ->writepage implementation, it will need to unlock the page.
    
    // bdev -- The device to write the page to
    // sector -- The offset on the device to write the page to (need not be aligned)
    // page -- The page to write
    // wbc -- The writeback_control for the write

    int err;
    err = orig_bdev_write_page(bdev, sector, page, wbc);
    printk(KERN_INFO KERNEL_MONITOR "Process %d bdev_write_page; dev: %d\n", current->pid, bdev->bd_dev);
    return err;
}

static asmlinkage ssize_t (*orig_random_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t hook_random_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    /* Вызов оригинального random_read() */
    int bytes_read;
    bytes_read = orig_random_read(file, buf, nbytes, ppos);
    printk(KERN_INFO KERNEL_MONITOR "Process %d read %d bytes from /dev/random\n", current->pid, bytes_read);
    return bytes_read;
}

static asmlinkage ssize_t (*orig_urandom_read)(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos);
static asmlinkage ssize_t hook_urandom_read(struct file *file, char __user *buf, size_t nbytes, loff_t *ppos)
{
    /* Вызов оригинального urandom_read() */
    int bytes_read;
    bytes_read = orig_urandom_read(file, buf, nbytes, ppos);
    printk(KERN_INFO KERNEL_MONITOR "Process %d read %d bytes from /dev/urandom\n", current->pid, bytes_read);    
    return bytes_read;
}

static struct ftrace_hook hooks[] = 
{
    HOOK("random_read", hook_random_read, &orig_random_read),
    HOOK("urandom_read", hook_urandom_read, &orig_urandom_read),
    HOOK("bdev_read_page", hook_bdev_read_page, &orig_bdev_read_page),
    HOOK("bdev_write_page", hook_bdev_write_page, &orig_bdev_write_page),
    HOOK("do_filp_open", hook_do_filp_open, &orig_do_filp_open),
    // HOOK("get_unused_fd_flags", hook_get_unused_fd_flags, &orig_get_unused_fd_flags),
    // HOOK("filp_close", hook_filp_close, &orig_filp_close)
};

/* Функция инициализации модуля */
static int __init kernel_monitor_init(void)
{
    unsigned long prev_nsec = ktime_get_ns();

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
    // __sys_call_table[__NR_mkdir]    = (unsigned long)hook_mkdir;

    __sys_call_table[__NR_open]     = (unsigned long)hook_open;
    __sys_call_table[__NR_close]    = (unsigned long)hook_close;
    __sys_call_table[__NR_read]     = (unsigned long)hook_read;
    __sys_call_table[__NR_write]    = (unsigned long)hook_write;

    /* Восстановить защиту от записи */
    protect_memory();

    unsigned long cur_nsec = ktime_get_ns();
    printk(KERN_INFO KERNEL_MONITOR "module loaded (%d ns)\n", cur_nsec - prev_nsec);
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