#include "../includes/L3SM.h"

static int security_hook_entry_filepermissions(struct kretprobe_instance* ri, struct pt_regs* regs);

static int security_hook_entry_inodepermissions(struct kretprobe_instance* ri, struct pt_regs* regs);

static int security_hook_entry_fileopen(struct kretprobe_instance* ri, struct pt_regs* regs);

const char* fileopen_hook_name = "security_file_open";
const char* filepermissions_hook_name = "security_file_permission";
const char* inodepermissions_hook_name = "security_inode_permission";

#define declare_kretprobe(NAME, ENTRY_CALLBACK, EXIT_CALLBACK, DATA_SIZE) 
static struct kretprobe NAME = {                                          \
	.handler	= EXIT_CALLBACK,	                          \
	.entry_handler	= ENTRY_CALLBACK,				  \
	.data_size	= DATA_SIZE,					  \
	.maxactive	= NR_CPUS,					  \
};

#define set_kretprobe(KPROBE)                                                       \
do {                                                                                \
    if(register_kretprobe(KPROBE)) {                                                \
        pr_err("MB EDR drv - unable to register a probe\n");                        \
        return -EINVAL;                                                             \
    }                                                                               \
} while(0)


declare_kretprobe(fileopen_probe, security_hook_entry_fileopen, security_hook_exit, 0);
declare_kretprobe(filepermissions_probe, security_hook_entry_filepermissions, security_hook_exit, 0);
declare_kretprobe(inodepermissions_probe, security_hook_entry_inodepermissions, security_hook_exit, 0);


int init_probbs()
{
    fileopen_probes.kp.symbol_name = fileopen_hook_name;
    set_kretprobe(&fileopen_probe);

    filepermissions_probe.kp.symbol_name = filepermissions_hook_name;
    set_kretprobe(&filepermissions_probe);

    inodepermissions_probe.kp.symbol_name = inodepermissions_hook_name;
    set_kretprobe(&inodepermissions_probe);
    return (0);
}

int exit_probbs()
{
    unregister_kretprobe(&fileopen_probe);
    unregister_kretprobe(&filepermissions_probe);
    unregister_kretprobe(&inodepermissions_probe);
    return (0);
}


int security_hook_entry_inodepermissions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk(KERN_INFO "L3SM - PROBES PART - INODE PERMISSION TRIGGERED \n");
    return (0);
}

int security_hook_entry_filepermissions(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk(KERN_INFO "L3SM - PROBES PART - FILE PERMISSION TRIGGERED \n");
    return (0);
}

int security_hook_entry_fileopen(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    printk(KERN_INFO "L3SM - PROBES PART - FILEOPEN TRIGGERED \n");
    return (0);
}


int security_hook_exit(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    //regs->ax = -EACCES;
    return 0;
}
