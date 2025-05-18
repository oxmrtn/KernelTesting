#include "../includes/L3SM.h"

static int security_hook_entry_filepermissions(struct kretprobe_instance* ri, struct pt_regs* regs);
static int security_hook_entry_inodepermissions(struct kretprobe_instance* ri, struct pt_regs* regs);
static int security_hook_entry_fileopen(struct kretprobe_instance* ri, struct pt_regs* regs);
static int security_hook_exit(struct kretprobe_instance* ri, struct pt_regs* regs);

const char* fileopen_hook_name = "security_file_open";
const char* filepermissions_hook_name = "security_file_permission";
const char* inodepermissions_hook_name = "security_inode_permission";

static struct kretprobe fileopen_probe = {
    .handler        = security_hook_exit,
    .entry_handler  = security_hook_entry_fileopen,
    .data_size      = 0,
    .maxactive      = NR_CPUS,
};

static struct kretprobe filepermissions_probe = {
    .handler        = security_hook_exit,
    .entry_handler  = security_hook_entry_filepermissions,
    .data_size      = 0,
    .maxactive      = NR_CPUS,
};

static struct kretprobe inodepermissions_probe = {
    .handler        = security_hook_exit,
    .entry_handler  = security_hook_entry_inodepermissions,
    .data_size      = 0,
    .maxactive      = NR_CPUS,
};

#define set_kretprobe(KPROBE)                                                       \
do {                                                                                \
    (KPROBE)->kp.symbol_name = (KPROBE == &fileopen_probe) ? fileopen_hook_name : \
                                (KPROBE == &filepermissions_probe) ? filepermissions_hook_name : \
                                inodepermissions_hook_name;                         \
    if (register_kretprobe(KPROBE)) {                                               \
        pr_err("L3SM - Failed to register kretprobe for %s\n", KPROBE->kp.symbol_name); \
        return -EINVAL;                                                             \
    } else {                                                                        \
        pr_info("L3SM - Registered kretprobe for %s\n", KPROBE->kp.symbol_name);    \
    }                                                                               \
} while (0)

int init_probbs(void)
{
    set_kretprobe(&fileopen_probe);
    set_kretprobe(&filepermissions_probe);
    set_kretprobe(&inodepermissions_probe);
    return 0;
}

int exit_probbs(void)
{
    unregister_kretprobe(&fileopen_probe);
    unregister_kretprobe(&filepermissions_probe);
    unregister_kretprobe(&inodepermissions_probe);
    return 0;
}

int security_hook_entry_inodepermissions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk(KERN_INFO "L3SM - PROBES PART - INODE PERMISSION TRIGGERED [pid=%d %s]\n", current->pid, current->comm);
    return 0;
}

int security_hook_entry_filepermissions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk(KERN_INFO "L3SM - PROBES PART - FILE PERMISSION TRIGGERED [pid=%d %s]\n", current->pid, current->comm);
    return 0;
}

int security_hook_entry_fileopen(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk(KERN_INFO "L3SM - PROBES PART - FILEOPEN TRIGGERED [pid=%d %s]\n", current->pid, current->comm);
    return 0;
}

int security_hook_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    //regs->ax = -EACCES;
    return 0;
}
