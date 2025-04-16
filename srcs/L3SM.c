#include "../includes/L3SM.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mtrullar");
MODULE_DESCRIPTION("Parser for LSM kernel module");
MODULE_VERSION("1.0");


char rule_buffer[BUF_SIZE];

static ssize_t proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
    char buf[BUF_SIZE];
    parsed_cmd_t cmd;

    if (count >= BUF_SIZE)
        return (-EINVAL);
    if (copy_from_user(buf, ubuf, count))
        return (-EFAULT);
    buf[count] = '\0';
    cmd = parse_line(buf);
    printk(KERN_INFO "[Parser] Command type: %d\n", cmd.type);
    if (cmd.type == CMD_ADD || cmd.type == CMD_REMOVE)
    {
        add_rule_to_list(&cmd.rule);
        snprintf(rule_buffer, BUF_SIZE,
                 "PATH: %s\nRULE: %s\nUID: %s\nUSER: %s\nGID: %s\nPID: %s\nRIGHT: %s\nALIAS: %s\n",
                 cmd.rule.path, cmd.rule.rule, cmd.rule.uid, cmd.rule.user,
                 cmd.rule.gid, cmd.rule.pid, cmd.rule.right, cmd.rule.alias);
        printk(KERN_INFO "  %s", rule_buffer);
    }
    else if (cmd.type == CMD_SWITCH) {
        snprintf(rule_buffer, BUF_SIZE, "SWITCH: %s <-> %s\n", cmd.arg1, cmd.arg2);
        printk(KERN_INFO "  %s", rule_buffer);
    }
    else if (cmd.type == CMD_DISPLAY)
    {
        display_rule_list();
    }
    free_cmd(&cmd);
    return (count);
}

static ssize_t proc_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    size_t len = strlen(rule_buffer);

    if (*ppos > 0 || count < len)
        return (0);

    if (copy_to_user(ubuf, rule_buffer, len))
        return (-EFAULT);
    *ppos = len;
    return (len);
}

static struct proc_ops proc_file_ops = 
{
    .proc_write = proc_write,
    .proc_read = proc_read,
};

static int __init rule_parser_init(void)
{
    struct proc_dir_entry *dir;

    dir = proc_mkdir(PROC_DIR_NAME, NULL);
    if (!dir)
    {
        printk(KERN_ERR "Failed to create /proc/L3SM directory\n");
        return (-ENOMEM);
    }
    if (!proc_create(PROC_FILE_NAME, 0666, dir, &proc_file_ops))
    {
        remove_proc_entry(PROC_DIR_NAME, NULL);
        printk(KERN_ERR "Failed to create /proc/L3SM/rule file\n");
        return (-ENOMEM);
    }

    printk(KERN_INFO "Rule Parser module loaded and /proc/L3SM/rule created.\n");
    return (0);
}

static void __exit rule_parser_exit(void)
{
    free_rule_list();
    remove_proc_entry(PROC_FILE_NAME, NULL);
    remove_proc_entry(PROC_DIR_NAME, NULL);
    printk(KERN_INFO "Rule Parser module unloaded and /proc/L3SM removed.\n");
}

module_init(rule_parser_init);
module_exit(rule_parser_exit);
