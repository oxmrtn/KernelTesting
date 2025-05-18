#include "../includes/L3SM.h"

static struct rule_node *rule_list_head = NULL;

void add_rule_to_list(rule_t *new_rule)
{
    struct rule_node *node = kmalloc(sizeof(struct rule_node), GFP_KERNEL);
    struct rule_node *cursor;

    if (!node)
        return;
    #define DUP(field) node->rule.field = new_rule->field ? kstrdup(new_rule->field, GFP_KERNEL) : NULL
    DUP(path); DUP(uid); DUP(user);
    DUP(gid); DUP(pid); DUP(right); DUP(alias);
    node->next = NULL;
    if (!rule_list_head)
    {
        rule_list_head = node;
        return;
    }
    cursor = rule_list_head;
    while (cursor->next)
        cursor = cursor->next;
    cursor->next = node;
}

int invalid_name(const char *name)
{
    if (!name)
        return (0);
    struct rule_node *curr = rule_list_head;
    while (curr)
    {
        if (strcmp(curr->rule.alias, name) == 0)
            return (1);
        curr = curr->next;
    }
    return (0);
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
            "PATH: %s\nUID: %s\nUSER: %s\nGID: %s\nPID: %s\nRIGHT: %s\nALIAS: %s\n",
            curr->rule.path, curr->rule.uid, curr->rule.user,
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

void switch_rules(int i, int j)
{
    struct rule_node *node1 = NULL;
    struct rule_node *node2 = NULL;
    struct rule_node *cursor = rule_list_head;
    int index = 0;
    if (i == j)
    {
        printk(KERN_INFO "[Switch] Nothing to do.\n");
        return;
    }
    while (cursor)
    {
        if (index == i)
            node1 = cursor;
        else if (index == j)
            node2 = cursor;
        if (node1 && node2)
            break;
        cursor = cursor->next;
        index++;
    }
    if (!node1 || !node2)
    {
        printk(KERN_ERR "[Switch] error : index out of bound. \n");
        return;
    }
    rule_t tmp = node1->rule;
    node1->rule = node2->rule;
    node2->rule = tmp;
    printk(KERN_INFO "[Switch] Swap is successfull.\n");
}

int find_rule_index_by_alias(const char *alias)
{
    struct rule_node *curr = rule_list_head;
    int index = 0;

    if (!alias)
        return (-1);
    while (curr)
    {
        if (curr->rule.alias && alias && strcmp(curr->rule.alias, alias) == 0)
            return (index);
        curr = curr->next;
        index++;
    }
    return (-1);
}

void remove_rule_by_index(int index)
{
    struct rule_node *curr = rule_list_head;
    struct rule_node *prev = NULL;
    int i = 0;

    while (curr && i < index)
    {
        prev = curr;
        curr = curr->next;
        i++;
    }
    if (!curr)
    {
        printk(KERN_ERR "[Remove] error : Index out of bound.\n");
        return;
    }
    if (!prev)
        rule_list_head = curr->next;
    else
        prev->next = curr->next;
    kfree(curr->rule.path);
    kfree(curr->rule.alias);
    kfree(curr);
}

