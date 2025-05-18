#include "../includes/L3SM.h"
#include "../includes/arch_regs.h"
#include <linux/kprobes.h>
#include <linux/sched.h>




static int hook_entry_file_permissions(struct kretprobe_instance *ri, struct pt_regs *regs);
static int hook_entry_inode_permissions(struct kretprobe_instance *ri, struct pt_regs *regs);
static int hook_entry_file_open(struct kretprobe_instance *ri, struct pt_regs *regs);
static int hook_exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs);


static const char *fileopen_hook_name        = "security_file_open";
static const char *filepermissions_hook_name = "security_file_permission";
static const char *inodepermissions_hook_name = "security_inode_permission";

static struct kretprobe fileopen_probe = {
    .handler        = hook_exit_handler,
    .entry_handler  = hook_entry_file_open,
    .data_size      = sizeof(struct probs_data),
    .maxactive      = NR_CPUS,
};

static struct kretprobe filepermissions_probe = {
    .handler        = hook_exit_handler,
    .entry_handler  = hook_entry_file_permissions,
    .data_size      = sizeof(struct probs_data),
    .maxactive      = NR_CPUS,
};

static struct kretprobe inodepermissions_probe = {
    .handler        = hook_exit_handler,
    .entry_handler  = hook_entry_inode_permissions,
    .data_size      = sizeof(struct probs_data),
    .maxactive      = NR_CPUS,
};

static inline int set_kretprobe(struct kretprobe *kp, const char *name)
{
    kp->kp.symbol_name = name;
    if (register_kretprobe(kp) < 0) {
        pr_err("L3SM - Registering kprobes failed%s\n", kp->kp.symbol_name);
        return -1;
    }
    pr_info("L3SM - Successfully registered kprobes %s\n", kp->kp.symbol_name);
    return (0);
}


int init_probes(void)
{
    if (set_kretprobe(&fileopen_probe, fileopen_hook_name) < 0)
        return -1;

    if (set_kretprobe(&filepermissions_probe, filepermissions_hook_name) < 0)
        return -1;

    if (set_kretprobe(&inodepermissions_probe, inodepermissions_hook_name) < 0)
        return -1;
    return 0;
}

int exit_probes(void)
{
    unregister_kretprobe(&fileopen_probe);
    unregister_kretprobe(&filepermissions_probe);
    unregister_kretprobe(&inodepermissions_probe);
    return 0;
}

char *get_path(const struct path *path)
{
    char *buf = kmalloc(PATH_MAX, GFP_KERNEL);
    char *path_str;

    if (!buf)
        return NULL;

    path_str = d_path(path, buf, PATH_MAX);
    if (IS_ERR(path_str)) {
        kfree(buf);
        return NULL;
    }
    return buf;
}

static int hook_entry_inode_permissions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probs_data *data = (struct probs_data *)ri->data;
    data->block = false;
    if (1) // NEED TO BE MODIFIED WITH RULES_MANAGER
    {
        struct inode *inode = (struct inode *)REG_ARG0(regs);
        struct dentry *dentry = NULL;
        struct path path;
        char *buf = NULL;
        char *pathname = NULL;

        dentry = d_find_alias(inode);
        if (!dentry)
            goto log_null;

        path.dentry = dentry;
        path.mnt = NULL;

        buf = kmalloc(PATH_MAX, GFP_KERNEL);
        if (!buf) {
            dput(dentry);
            return 1;
        }

        pathname = dentry_path_raw(dentry, buf, PATH_MAX);
        if (!IS_ERR(pathname)) {
            log_kern(current->pid, pathname);
            log_proc(current->pid, pathname);
        }
        else
        {
            log_null:
            log_kern(current->pid, NULL);
            log_proc(current->pid, NULL);
        }

        if (dentry)
            dput(dentry);
        kfree(buf);
    }
    return 0;
}


static int hook_entry_file_permissions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probs_data *data;

    data = (struct probs_data *)ri->data;
    data->block = false;
    printk(KERN_INFO "L3SM - PROBES - FILE PERMISSION TRIGGERED [pid=%d %s]\n", current->pid, current->comm);

    if (1) // NEED TO BE MODIFIED WITH RULES_MANAGER
    {
        struct file *file = (struct file *)REG_ARG0(regs);
        char * path;

        path = get_path(&file->f_path);
        log_kern(current->pid, path);
        log_proc(current->pid, path);
        kfree(path);
    }
    return 0;
}

static int hook_entry_file_open(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probs_data *data;

    data = (struct probs_data *)ri->data;
    data->block = false;
    printk(KERN_INFO "L3SM - PROBES - FILE OPEN TRIGGERED [pid=%d %s]\n", current->pid, current->comm);
    if (1) // NEED TO BE MODIFIED WITH RULES_MANAGER
    {
        struct file *file = (struct file *)REG_ARG0(regs);
        char * path;

        path = get_path(&file->f_path);
        log_kern(current->pid, path);
        log_proc(current->pid, path);
        kfree(path);
        data->block = true;
    }
    return 0;
}

static int hook_exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probs_data *data = (struct probs_data *)ri->data;

    if (data && data->block)
        SET_RET(regs, -EACCES);
    return 0;
}
