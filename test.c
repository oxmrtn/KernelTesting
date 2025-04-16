#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>

#define PROC_DIR_NAME "l3SM"
#define PROC_FILE_NAME "rules"
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

struct rule_node {
    rule_t rule;
    struct rule_node *next;
};

static struct rule_node *rule_list_head = NULL;


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

static void add_rule_to_list(rule_t *new_rule)
{
    struct rule_node *node = kmalloc(sizeof(struct rule_node), GFP_KERNEL);
    if (!node) return;

    // Allouer et copier chaque champ (si non NULL)
    #define DUP(field) node->rule.field = new_rule->field ? kstrdup(new_rule->field, GFP_KERNEL) : NULL

    DUP(path); DUP(rule); DUP(uid); DUP(user);
    DUP(gid); DUP(pid); DUP(right); DUP(alias);

    node->next = rule_list_head;
    rule_list_head = node;
}

static void display_all_rules(void)
{
    struct rule_node *curr = rule_list_head;
    char *p = rule_buffer;
    int remaining = BUF_SIZE;

    p[0] = '\0';

    while (curr && remaining > 0) {
        int written = snprintf(p, remaining,
            "PATH: %s\nRULE: %s\nUID: %s\nUSER: %s\nGID: %s\nPID: %s\nRIGHT: %s\nALIAS: %s\n\n",
            curr->rule.path ?: "-", curr->rule.rule ?: "-", curr->rule.uid ?: "-",
            curr->rule.user ?: "-", curr->rule.gid ?: "-", curr->rule.pid ?: "-",
            curr->rule.right ?: "-", curr->rule.alias ?: "-");
        if (written < 0 || written >= remaining)
            break;
        p += written;
        remaining -= written;
        curr = curr->next;
    }
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

static void display_rule_list(void)
{
    int i = 0;
    struct rule node *curr = rule_list_head;
    while (curr)
    {
        struct rule_node *tmp = curr->next;
        snprintf(rule_buffer, BUF_SIZE,
            "PATH: %s\nRULE: %s\nUID: %s\nUSER: %s\nGID: %s\nPID: %s\nRIGHT: %s\nALIAS: %s\n",
            curr.rule.path, curr.rule.rule, curr.rule.uid, curr.rule.user,
            curr.rule.gid, curr.rule.pid, curr.rule.right, curr.rule.alias);
        printk(KERN_INFO "%d:   %s\n", i, rule_buffer);
        i++;
        curr = tmp;
    }
}

static void free_rule_list(void)
{
    struct rule_node *curr = rule_list_head;
    while (curr)
    {
        struct rule_node *tmp = curr->next;
        kfree(curr->rule.path);
        kfree(curr->rule.rule);
        kfree(curr->rule.uid);
        kfree(curr->rule.user);
        kfree(curr->rule.gid);
        kfree(curr->rule.pid);
        kfree(curr->rule.right);
        kfree(curr->rule.alias);
        kfree(curr);
        curr = tmp;
    }
}


// Buffer pour stocker les règles
static char rule_buffer[BUF_SIZE];

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
    return count;
}

static ssize_t proc_read(struct file *file, char __user *ubuf, size_t count, loff_t *ppos)
{
    size_t len = strlen(rule_buffer);

    if (*ppos > 0 || count < len)
        return 0;

    if (copy_to_user(ubuf, rule_buffer, len))
        return -EFAULT;

    *ppos = len;
    return len;
}

static struct proc_ops proc_file_ops = {
    .proc_write = proc_write,
    .proc_read = proc_read,
};

static int __init rule_parser_init(void)
{
    struct proc_dir_entry *dir;

    dir = proc_mkdir(PROC_DIR_NAME, NULL);
    if (!dir) {
        printk(KERN_ERR "Failed to create /proc/l3SM directory\n");
        return -ENOMEM;
    }

    if (!proc_create(PROC_FILE_NAME, 0666, dir, &proc_file_ops)) {
        remove_proc_entry(PROC_DIR_NAME, NULL);
        printk(KERN_ERR "Failed to create /proc/l3SM/rules file\n");
        return -ENOMEM;
    }

    printk(KERN_INFO "Rule Parser module loaded and /proc/l3SM/rules created.\n");
    return 0;
}

static void __exit rule_parser_exit(void)
{
    free_rule_list();
    remove_proc_entry(PROC_FILE_NAME, NULL);
    remove_proc_entry(PROC_DIR_NAME, NULL);
    printk(KERN_INFO "Rule Parser module unloaded and /proc/l3SM removed.\n");
}

module_init(rule_parser_init);
module_exit(rule_parser_exit);
