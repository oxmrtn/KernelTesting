#include "../includes/L3SM.h"


static struct rule_node *rule_list_head = NULL;

void add_rule_to_list(rule_t *new_rule)
{
    struct rule_node *node = kmalloc(sizeof(struct rule_node), GFP_KERNEL);

    if (!node)
        return;
    #define DUP(field) node->rule.field = new_rule->field ? kstrdup(new_rule->field, GFP_KERNEL) : NULL
    DUP(path); DUP(rule); DUP(uid); DUP(user);
    DUP(gid); DUP(pid); DUP(right); DUP(alias);
    node->next = rule_list_head;
    rule_list_head = node;
}

void display_rule_list(void)
{
    int i = 0;
    struct rule_node *curr = rule_list_head;
    while (curr)
    {
        static char r_buffer[1024];
        struct rule_node *tmp = curr->next;
        snprintf(r_buffer, BUF_SIZE,
            "PATH: %s\nRULE: %s\nUID: %s\nUSER: %s\nGID: %s\nPID: %s\nRIGHT: %s\nALIAS: %s\n",
            curr->rule.path, curr->rule.rule, curr->rule.uid, curr->rule.user,
            curr->rule.gid, curr->rule.pid, curr->rule.right, curr->rule.alias);
        printk(KERN_INFO "%d:   %s\n", i, r_buffer);
        i++;
        curr = tmp;
    }
}

void free_rule_list(void)
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
        curr = tmp;
    }
    return ;
}

