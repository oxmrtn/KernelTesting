#include "../includes/L3SM.h"
#include <linux/kprobes.h>
#include <linux/sched.h>  // pour current->pid, current->comm

// Prototypes des handlers
static int hook_entry_file_permissions(struct kretprobe_instance *ri, struct pt_regs *regs);
static int hook_entry_inode_permissions(struct kretprobe_instance *ri, struct pt_regs *regs);
static int hook_entry_file_open(struct kretprobe_instance *ri, struct pt_regs *regs);
static int hook_exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs);

// Symboles cibles
static const char *fileopen_hook_name        = "security_file_open";
static const char *filepermissions_hook_name = "security_file_permission";
static const char *inodepermissions_hook_name = "security_inode_permission";

// Déclaration des probes
static struct kretprobe fileopen_probe = {
    .handler        = hook_exit_handler,
    .entry_handler  = hook_entry_file_open,
    .data_size      = 0,
    .maxactive      = NR_CPUS,
};

static struct kretprobe filepermissions_probe = {
    .handler        = hook_exit_handler,
    .entry_handler  = hook_entry_file_permissions,
    .data_size      = 0,
    .maxactive      = NR_CPUS,
};

static struct kretprobe inodepermissions_probe = {
    .handler        = hook_exit_handler,
    .entry_handler  = hook_entry_inode_permissions,
    .data_size      = 0,
    .maxactive      = NR_CPUS,
};

// Macro d'enregistrement de kretprobe
static inline int set_kretprobe(struct kretprobe *kp, const char *name)
{
    kp->kp.symbol_name = name;
    if (register_kretprobe(kp) < 0) {
        pr_err("L3SM - Failed to register kretprobe for %s\n", kp->kp.symbol_name);
        return -1;
    }
    pr_info("L3SM - Registered kretprobe for %s\n", kp->kp.symbol_name);
    return 0;
}

// Initialisation des probes
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

// Nettoyage des probes
int exit_probes(void)
{
    unregister_kretprobe(&fileopen_probe);
    unregister_kretprobe(&filepermissions_probe);
    unregister_kretprobe(&inodepermissions_probe);
    return 0;
}

// Handlers d'entrée
static int hook_entry_inode_permissions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk(KERN_INFO "L3SM - PROBES - INODE PERMISSION TRIGGERED [pid=%d %s]\n", current->pid, current->comm);
    return 0;
}

static int hook_entry_file_permissions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk(KERN_INFO "L3SM - PROBES - FILE PERMISSION TRIGGERED [pid=%d %s]\n", current->pid, current->comm);
    return 0;
}

static int hook_entry_file_open(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk(KERN_INFO "L3SM - PROBES - FILE OPEN TRIGGERED [pid=%d %s]\n", current->pid, current->comm);
    return 0;
}

// Handler de sortie
static int hook_exit_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    // Exemple : blocage possible de l'appel
    // regs->ax = -EACCES;
    return 0;
}
