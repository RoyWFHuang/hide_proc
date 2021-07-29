#include <linux/cdev.h>
#include <linux/ftrace.h>
#include <linux/kallsyms.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/pid.h>
#include <linux/bitmap.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("National Cheng Kung University, Taiwan");

enum RETURN_CODE { SUCCESS };

struct ftrace_hook {
    const char *name;
    void *func, *orig;
    unsigned long address;
    struct ftrace_ops ops;
};

static int hook_resolve_addr(struct ftrace_hook *hook)
{
    hook->address = kallsyms_lookup_name(hook->name);
    if (!hook->address) {
        printk("unresolved symbol: %s\n", hook->name);
        return -ENOENT;
    }
    *((unsigned long *) hook->orig) = hook->address;
    return 0;
}

static void notrace hook_ftrace_thunk(unsigned long ip,
                                      unsigned long parent_ip,
                                      struct ftrace_ops *ops,
                                      struct pt_regs *regs)
{
    struct ftrace_hook *hook = container_of(ops, struct ftrace_hook, ops);
    if (!within_module(parent_ip, THIS_MODULE))
        regs->ip = (unsigned long) hook->func;
}

static int hook_install(struct ftrace_hook *hook)
{
    int err = hook_resolve_addr(hook);
    if (err)
        return err;

    hook->ops.func = hook_ftrace_thunk;
    hook->ops.flags = FTRACE_OPS_FL_SAVE_REGS | FTRACE_OPS_FL_RECURSION_SAFE |
                      FTRACE_OPS_FL_IPMODIFY;

    err = ftrace_set_filter_ip(&hook->ops, hook->address, 0, 0);
    if (err) {
        printk("ftrace_set_filter_ip() failed: %d\n", err);
        return err;
    }

    err = register_ftrace_function(&hook->ops);
    if (err) {
        printk("register_ftrace_function() failed: %d\n", err);
        ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
        return err;
    }
    return 0;
}


void hook_remove(struct ftrace_hook *hook)
{
    int err = unregister_ftrace_function(&hook->ops);
    if (err)
        printk("unregister_ftrace_function() failed: %d\n", err);
    err = ftrace_set_filter_ip(&hook->ops, hook->address, 1, 0);
    if (err)
        printk("ftrace_set_filter_ip() failed: %d\n", err);
}

DECLARE_BITMAP(hid_prc_bmap, PID_MAX_LIMIT);
// typedef struct {
//     pid_t id;
//     struct list_head list_node;
// } pid_node_t;

// LIST_HEAD(hidden_proc);

typedef struct pid *(*find_ge_pid_func)(int nr, struct pid_namespace *ns);
static find_ge_pid_func real_find_ge_pid;

static struct ftrace_hook hook;

static bool is_hidden_proc(pid_t pid)
{
    return test_bit(pid, hid_prc_bmap);
    // pid_node_t *proc, *tmp_proc;
    // list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
    //     if (proc->id == pid)
    //         return true;
    // }
    // return false;
}

static struct pid *hook_find_ge_pid(int nr, struct pid_namespace *ns)
{
    struct pid *pid = real_find_ge_pid(nr, ns);

    while (pid && is_hidden_proc(pid->numbers->nr))
    {
        printk(KERN_INFO "@ %s pid(%d) is hidden \n",
            __func__, pid->numbers->nr);
        pid = real_find_ge_pid(pid->numbers->nr + 1, ns);
    }
    return pid;
}
EXPORT_SYMBOL(hook_find_ge_pid);

static void init_hook(void)
{
    real_find_ge_pid = (find_ge_pid_func) kallsyms_lookup_name("find_ge_pid");
    hook.name = "find_ge_pid";
    hook.func = hook_find_ge_pid;
    hook.orig = &real_find_ge_pid;
    hook_install(&hook);
}

static int hide_process(pid_t pid)
{
    // pid_node_t *proc = NULL;
    struct pid *t_chpid = NULL;
    if (1 == pid)
        return SUCCESS;
    t_chpid = find_get_pid(pid);
    if (NULL == t_chpid) {
        printk(KERN_INFO "@ %d not exist\n", pid);
        return -ENOENT;
    }
    if (is_hidden_proc(pid))
        return SUCCESS;
    // proc = kzalloc(sizeof(pid_node_t), GFP_KERNEL);
    // if(NULL == proc)
    //     return -ENOMEM;
    // proc->id = pid;
    // list_add_tail(&proc->list_node, &hidden_proc);
    set_bit(pid, hid_prc_bmap);
    return SUCCESS;
}

static int unhide_process(pid_t pid)
{
    clear_bit(pid, hid_prc_bmap);
    // pid_node_t *proc, *tmp_proc;
    // list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
    //     if(proc->id == pid) {
    //         list_del(&proc->list_node);
    //         kfree(proc);
    //     }
    // }
    return SUCCESS;
}

#define OUTPUT_BUFFER_FORMAT "pid: %d\n"
#define MAX_MESSAGE_SIZE (sizeof(OUTPUT_BUFFER_FORMAT) + 4)

static pid_t _getppid(long pid){

    struct pid *t_chpid = NULL, *t_ppid = NULL;
    struct task_struct *ch_ts = NULL;
    pid_t ppid;

    t_chpid = find_get_pid(pid);
    if (NULL == t_chpid) {
        printk(KERN_INFO "@ %ld not exist\n", pid);
        return -ENOENT;
    }
    ch_ts = get_pid_task(t_chpid, PIDTYPE_PID);
    ppid = task_ppid_nr(ch_ts);
    t_ppid = find_get_pid(ppid);
    if (NULL == t_ppid) {
        printk(KERN_INFO "@ %d not exist\n", ppid);
        return -ENOENT;
    }
    printk(KERN_INFO "@ %ld parent is %d\n", pid, ppid);
    return ppid;
}

static int device_open(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static int device_close(struct inode *inode, struct file *file)
{
    return SUCCESS;
}

static ssize_t device_read(struct file *filep,
                           char *buffer,
                           size_t len,
                           loff_t *offset)
{
    // pid_node_t *proc, *tmp_proc;
    int idx = 0;
    char message[MAX_MESSAGE_SIZE];
    if (*offset)
        return 0;

    for (idx = 0; idx < PID_MAX_LIMIT; idx++) {
        if(test_bit(idx, hid_prc_bmap)){
            memset(message, 0, MAX_MESSAGE_SIZE);
            sprintf(message, OUTPUT_BUFFER_FORMAT, idx);
            copy_to_user(buffer + *offset, message, strlen(message));
            *offset += strlen(message);
        }
    }

    // list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
    //     memset(message, 0, MAX_MESSAGE_SIZE);
    //     sprintf(message, OUTPUT_BUFFER_FORMAT, proc->id);
    //     copy_to_user(buffer + *offset, message, strlen(message));
    //     *offset += strlen(message);
    // }
    return *offset;
}

static ssize_t device_write(struct file *filep,
                            const char *buffer,
                            size_t len,
                            loff_t *offset)
{
    long pid;
    char *message = NULL;
    pid_t ppid;
    int ret;
    char add_message[] = "add", del_message[] = "del";
    if (len < sizeof(add_message) - 1 && len < sizeof(del_message) - 1)
        return -EAGAIN;

    message = kzalloc(len + 1, GFP_KERNEL);
    if(NULL == message)
        return -ENOMEM;
    // memset(message, 0, len + 1);
    copy_from_user(message, buffer, len);
    if (!memcmp(message, add_message, sizeof(add_message) - 1)) {
        kstrtol(message + sizeof(add_message), 10, &pid);
        if (SUCCESS != (ret = hide_process(pid)) ) {
            kfree(message);
            return ret;
        }
        if (ENOENT != (ppid = _getppid(pid))) {
            hide_process(ppid);
        }
    } else if (!memcmp(message, del_message, sizeof(del_message) - 1)) {
        kstrtol(message + sizeof(del_message), 10, &pid);
        unhide_process(pid);
        ppid = _getppid(pid);
        unhide_process(ppid);
    } else {
        kfree(message);
        return -EAGAIN;
    }

    *offset = len;
    kfree(message);
    return len;
}

static struct cdev cdev;
static struct class *hideproc_class = NULL;
static dev_t dev;
static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = device_open,
    .release = device_close,
    .read = device_read,
    .write = device_write,
};

#define MINOR_VERSION 1
#define DEVICE_NAME "hideproc"

// static void _clear_all_hideproc(void)
// {
//     pid_node_t *proc, *tmp_proc;
//     list_for_each_entry_safe (proc, tmp_proc, &hidden_proc, list_node) {
//         list_del(&proc->list_node);
//         kfree(proc);
//     }
// }

static int _hideproc_init(void)
{
    int dev_major;
    struct device *device = NULL;
    printk(KERN_INFO "@ %s\n", __func__);
    if (0 != alloc_chrdev_region(&dev, 0, MINOR_VERSION, DEVICE_NAME) )
        goto fail_hideproc_init;

    dev_major = MAJOR(dev);

    hideproc_class = class_create(THIS_MODULE, DEVICE_NAME);
    if(NULL == hideproc_class)
        goto fail_hideproc_init;

    cdev_init(&cdev, &fops);
    if(0 != cdev_add(&cdev, MKDEV(dev_major, MINOR_VERSION), 1))
         goto fail_hideproc_init_cdev_add;
    device = device_create(hideproc_class, NULL, MKDEV(dev_major, MINOR_VERSION), NULL,
                  DEVICE_NAME);
    if (NULL == device)
        goto fail_hideproc_init_dev_create;
    init_hook();
    return 0;
fail_hideproc_init_dev_create:
    cdev_del(&cdev);
fail_hideproc_init_cdev_add:
    class_destroy(hideproc_class);
fail_hideproc_init:
    return -1;
}

static void _hideproc_exit(void)
{
    printk(KERN_INFO "@ %s\n", __func__);
    // _clear_all_hideproc();
    hook_remove(&hook);
    device_destroy(hideproc_class, MKDEV(MAJOR(dev), MINOR_VERSION));
    class_destroy(hideproc_class);
    cdev_del(&cdev);
    unregister_chrdev_region(MKDEV(MAJOR(dev), MINOR_VERSION), 1);
    /* FIXME: ensure the release of all allocated resources */
}

module_init(_hideproc_init);
module_exit(_hideproc_exit);