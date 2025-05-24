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


// Struct to do things
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
//  Init the Kretprobes
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
// Delete the kreprobes
{
    unregister_kretprobe(&fileopen_probe);
    unregister_kretprobe(&filepermissions_probe);
    unregister_kretprobe(&inodepermissions_probe);
    return 0;
}

// Tranform the path struct to a char *
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
    path_str = kstrdup(path_str, GFP_KERNEL);
    kfree(buf);
    return path_str;
}

static int hook_entry_inode_permissions(struct kretprobe_instance *ri, struct pt_regs *regs)
// Handler for the inode_permission hooks probed
{
    struct probs_data *data = (struct probs_data *)ri->data;
    const struct cred *cred = current_cred();
    data->block = false;
    struct inode *inode = (struct inode *)REG_ARG0(regs);
    int mask = (int)REG_ARG2(regs);
    struct dentry *dentry = NULL;
    char *buf = NULL;
    char *pathname = NULL;

    dentry = d_find_alias(inode);
    if (!dentry)
        goto done;
    buf = kmalloc(PATH_MAX, GFP_KERNEL);
    if (!buf) {
        dput(dentry);
        return 1;
    }
    pathname = dentry_path_raw(dentry, buf, PATH_MAX);
    if (IS_ERR(pathname))
        pathname = NULL;
    data->path = kstrdup(pathname, GFP_KERNEL);
    if (rule_check_access(cred->uid, cred->gid, current->pid, mask, pathname))
    {
        data->block = true;
    }
    done:
    if (dentry)
        dput(dentry);
    kfree(buf);
    return 0;
}


static int hook_entry_file_permissions(struct kretprobe_instance *ri, struct pt_regs *regs)
// Handler for the file_permission hooks probed
{
    struct probs_data *data;
    const struct cred *cred = current_cred();
    int mask = (int)REG_ARG2(regs);
    struct file *file = (struct file *)REG_ARG0(regs);
    char * path;

    data = (struct probs_data *)ri->data;
    data->block = false;
    path = get_path(&file->f_path);
    data->path = path;
    if (rule_check_access(cred->uid, cred->gid, current->pid, mask, path))
    {
        data->block = true;
    }
    return 0;
}

static int hook_entry_file_open(struct kretprobe_instance *ri, struct pt_regs *regs)
// Handler for the file_open hooks probed
{
    struct probs_data *data = (struct probs_data *)ri->data;
    const struct cred *cred = current_cred();
    struct file *file = (struct file *)REG_ARG0(regs);
    char *path;

    data->block = false;
    path = get_path(&file->f_path);
    data->path = path;
    if (rule_check_access(cred->uid, cred->gid, current->pid, L3SM_RIGHT_OPEN, path))
    {
        data->block = true;
    }
    return 0;
}

static int hook_exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct probs_data *data = (struct probs_data *)ri->data;

    if (data && data->block)
    {
        log_kern(current->pid, data->path);
        log_proc(current->pid, data->path);
        SET_RET(regs, -EACCES);
    }
    if (data->path)
        kfree(data->path);
    return 0;
}
