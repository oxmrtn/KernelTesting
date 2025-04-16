#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define PROC_NAME "customcmd"
#define BUF_SIZE 512

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Toi");
MODULE_DESCRIPTION("Module parseur de commandes LSM");
MODULE_VERSION("1.0");

typedef enum {
    CMD_ADD,
    CMD_REMOVE,
    CMD_DISPLAY,
    CMD_SWITCH,
    CMD_UNKNOWN
} cmd_type_t;

typedef struct {
    char *path;
    char *rule;
    char *uid;
    char *user;
    char *gid;
    char *pid;
    char *right;
    char *alias;
} rule_t;

typedef struct {
    cmd_type_t type;
    rule_t rule;
    char *arg1;
    char *arg2;
} parsed_cmd_t;

static char *extract_value(const char *input)
{
    const char *start = strchr(input, '\"');
    const char *end = strrchr(input, '\"');
    char *value;

    if (!start || !end || start == end)
        return NULL;

    value = kmalloc(end - start, GFP_KERNEL);
    if (!value) return NULL;

    strncpy(value, start + 1, end - start - 1);
    value[end - start - 1] = '\0';

    return value;
}

static cmd_type_t get_cmd_type(const char *line)
{
    if (strncmp(line, "ADD", 3) == 0) return CMD_ADD;
    if (strncmp(line, "REMOVE", 6) == 0) return CMD_REMOVE;
    if (strncmp(line, "DISPLAY", 7) == 0) return CMD_DISPLAY;
    if (strncmp(line, "SWITCH", 6) == 0) return CMD_SWITCH;
    return CMD_UNKNOWN;
}

static void parse_arguments(parsed_cmd_t *cmd, const char *args)
{
    char *copy = kstrdup(args, GFP_KERNEL);
    char *token, *p;

    if (!copy) return;

    p = copy;
    while ((token = strsep(&p, ";")) != NULL) {
        while (*token == ' ') token++;

        if (strncmp(token, "PATH(", 5) == 0)
            cmd->rule.path = extract_value(token);
        else if (strncmp(token, "RULE(", 5) == 0)
            cmd->rule.rule = extract_value(token);
        else if (strncmp(token, "UID(", 4) == 0)
            cmd->rule.uid = extract_value(token);
        else if (strncmp(token, "USER(", 5) == 0)
            cmd->rule.user = extract_value(token);
        else if (strncmp(token, "GID(", 4) == 0)
            cmd->rule.gid = extract_value(token);
        else if (strncmp(token, "PID(", 4) == 0)
            cmd->rule.pid = extract_value(token);
        else if (strncmp(token, "RIGHT(", 6) == 0)
            cmd->rule.right = extract_value(token);
        else if (strncmp(token, "AS(", 3) == 0)
            cmd->rule.alias = extract_value(token);
    }

    kfree(copy);
}

static parsed_cmd_t parse_line(const char *line)
{
    parsed_cmd_t cmd = {0};
    char *args, *start, *end;

    cmd.type = get_cmd_type(line);

    start = strchr(line, '(');
    end = strrchr(line, ')');
    if (!start || !end || start >= end)
        return cmd;

    args = kmalloc(end - start, GFP_KERNEL);
    if (!args) return cmd;

    strncpy(args, start + 1, end - start - 1);
    args[end - start - 1] = '\0';

    if (cmd.type == CMD_ADD || cmd.type == CMD_REMOVE) {
        parse_arguments(&cmd, args);
    } else if (cmd.type == CMD_SWITCH) {
        char *first = extract_value(args);
        char *next_quote = strchr(args + 1, '\"');
        next_quote = next_quote ? strchr(next_quote + 1, '\"') : NULL;
        char *second = NULL;
        if (next_quote)
            second = extract_value(next_quote - 1);

        cmd.arg1 = first;
        cmd.arg2 = second;
    }

    kfree(args);
    return cmd;
}

static void free_cmd(parsed_cmd_t *cmd)
{
    kfree(cmd->rule.path);
    kfree(cmd->rule.rule);
    kfree(cmd->rule.uid);
    kfree(cmd->rule.user);
    kfree(cmd->rule.gid);
    kfree(cmd->rule.pid);
    kfree(cmd->rule.right);
    kfree(cmd->rule.alias);
    kfree(cmd->arg1);
    kfree(cmd->arg2);
}

static ssize_t proc_write(struct file *file, const char __user *ubuf, size_t count, loff_t *ppos)
{
    char buf[BUF_SIZE];
    parsed_cmd_t cmd;

    if (count >= BUF_SIZE)
        return -EINVAL;

    if (copy_from_user(buf, ubuf, count))
        return -EFAULT;

    buf[count] = '\0';

    cmd = parse_line(buf);

    printk(KERN_INFO "[Parser] Command type: %d\n", cmd.type);
    if (cmd.type == CMD_ADD || cmd.type == CMD_REMOVE) {
        printk(KERN_INFO "  PATH: %s\n", cmd.rule.path);
        printk(KERN_INFO "  RULE: %s\n", cmd.rule.rule);
        printk(KERN_INFO "  UID: %s\n", cmd.rule.uid);
        printk(KERN_INFO "  USER: %s\n", cmd.rule.user);
        printk(KERN_INFO "  GID: %s\n", cmd.rule.gid);
        printk(KERN_INFO "  PID: %s\n", cmd.rule.pid);
        printk(KERN_INFO "  RIGHT: %s\n", cmd.rule.right);
        printk(KERN_INFO "  ALIAS: %s\n", cmd.rule.alias);
    } else if (cmd.type == CMD_SWITCH) {
        printk(KERN_INFO "  SWITCH: %s <-> %s\n", cmd.arg1, cmd.arg2);
    }

    free_cmd(&cmd);
    return count;
}

static struct proc_ops proc_file_ops = {
    .proc_write = proc_write,
};

static int __init rule_parser_init(void)
{
    proc_create(PROC_NAME, 0666, NULL, &proc_file_ops);
    printk(KERN_INFO "Rule Parser module loaded.\n");
    return 0;
}

static void __exit rule_parser_exit(void)
{
    remove_proc_entry(PROC_NAME, NULL);
    printk(KERN_INFO "Rule Parser module unloaded.\n");
}

module_init(rule_parser_init);
module_exit(rule_parser_exit);
