#include "../includes/L3SM.h"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("mtrullar");
MODULE_DESCRIPTION("Parser for LSM kernel module");
MODULE_VERSION("1.0");


char rule_buffer[BUF_SIZE];
char log_buffer[BUF_SIZE];

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
    if (cmd.type == CMD_ADD)
    {
        add_rule_to_list(&cmd.rule);
        // snprintf(rule_buffer, BUF_SIZE,
        //          "PATH: %s\nRULE: %s\nUID: %s\nUSER: %s\nGID: %s\nPID: %s\nRIGHT: %s\nALIAS: %s\n",
        //          cmd.rule.path, cmd.rule.rule, cmd.rule.uid, cmd.rule.user,
        //          cmd.rule.gid, cmd.rule.pid, cmd.rule.right, cmd.rule.alias);
        // printk(KERN_INFO "  %s", rule_buffer);
    }
    else if (cmd.type == CMD_SWITCH)
    {
        int index1 = -1, index2 = -1;
    
        if (cmd.arg1 && strspn(cmd.arg1, "0123456789") == strlen(cmd.arg1))
            index1 = simple_strtol(cmd.arg1, NULL, 10);
        else
            index1 = find_rule_index_by_alias(cmd.arg1);
        if (cmd.arg2 && strspn(cmd.arg2, "0123456789") == strlen(cmd.arg2))
            index2 = simple_strtol(cmd.arg2, NULL, 10);
        else
            index2 = find_rule_index_by_alias(cmd.arg2);
        if (index1 >= 0 && index2 >= 0)
            switch_rules(index1, index2);
        else
            printk(KERN_ERR "[Switch] error : rules not found \n");
    }
    else if (cmd.type == CMD_DISPLAY)
    {
        display_rule_list();
    }
    else if (cmd.type == CMD_REMOVE)
    {
        int index = -1;
        if (cmd.arg1 && strspn(cmd.arg1, "0123456789") == strlen(cmd.arg1))
            index = simple_strtol(cmd.arg1, NULL, 10);
        else
            index = find_rule_index_by_alias(cmd.arg1);
    
        if (index >= 0)
            remove_rule_by_index(index);
        else
            printk(KERN_ERR "[Remove] error : rules not found.\n");
    }
    else if (cmd.type == CMD_UNKNOWN)
    {
        printk(KERN_ERR "error: Syntax error detected. \n");
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

static ssize_t log_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    struct log_chain *current_node = logs_list_head;
    char *buf;
    size_t len = 0;

    if (*ppos > 0)
        return 0;
    buf = kmalloc(PAGE_SIZE, GFP_KERNEL);
    if (!buf)
        return -ENOMEM;
    buf[0] = '\0';
    while (current_node && len < PAGE_SIZE - 256) {
        if (current_node->log) {
            len += scnprintf(buf + len, PAGE_SIZE - len, "%s\n", current_node->log);
        }
        current_node = current_node->next;
    }
    if (copy_to_user(ubuf, buf, len)) {
        kfree(buf);
        return -EFAULT;
    }
    *ppos = len;
    kfree(buf);
    return len;
}

static struct proc_ops proc_file_ops = 
{
    .proc_write = proc_write,
    .proc_read = proc_read,
};

static struct proc_ops proc_logs_ops = 
{
    .proc_read = log_read,
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
    if (!proc_create(PROC_FILE_LOG, 0666, dir, &proc_logs_ops))
    {
        remove_proc_entry(PROC_FILE_NAME, NULL);
        remove_proc_entry(PROC_DIR_NAME, NULL);
        printk(KERN_ERR "Failed to create /proc/L3SM/logs file\n");
        return (-ENOMEM);
    }
    if (init_probes() == -1)
    {
        printk(KERN_ERR "error: Probes cannot be created\n");
    }
    printk(KERN_INFO "Rule Parser module loaded, /proc/L3SM/rule and /proc/L3SM/logs created.\n");
    return (0);
}

static void __exit rule_parser_exit(void)
{
    free_rule_list();
    free_logs();
    remove_proc_entry(PROC_FILE_NAME, NULL);
    remove_proc_entry(PROC_DIR_NAME, NULL);
    printk(KERN_INFO "Rule Parser module unloaded and /proc/L3SM removed.\n");
}

module_init(rule_parser_init);
module_exit(rule_parser_exit);
