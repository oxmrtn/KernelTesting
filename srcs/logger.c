#include "../includes/L3SM.h"

struct log_chain *logs_list_head = NULL;

int log_kern(int pid, char *path)
// Display a log in the KERN_INFO terminal
{
    struct timespec64 ts;
    struct tm tm;
    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);
    printk(KERN_INFO "[L3SM] %04ld:%02d:%02d:%02d:%02d:%02d The process %d tried to accessed %s and was denied.\n", tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec, pid, (path ? path : "UNKNOW"));
    return (0);
}

int log_proc(int pid, char *path)
// Add a log to the log linked list
{
    struct timespec64 ts;
    struct tm tm;
    ktime_get_real_ts64(&ts);
    time64_to_tm(ts.tv_sec, 0, &tm);
    char buf[256];
    snprintf(buf, sizeof(buf), "[L3SM] %04ld:%02d:%02d:%02d:%02d:%02d The process %d tried to access %s and was denied.\n",
                tm.tm_year + 1900,
                tm.tm_mon + 1,
                tm.tm_mday,
                tm.tm_hour,
                tm.tm_min,
                tm.tm_sec,
                pid, path ? path : "UNKNOWN");
    add_log(buf);
    return (0);
}

static void push_back_logs(struct log_chain *to_add)
// Add a log_chain struct to the back on the logs_list_head chain
{
    struct log_chain *current_node = logs_list_head;

    if (!current_node)
    {
        logs_list_head = to_add;
        return ;
    }
    while (current_node && current_node->next)
        current_node = current_node->next;
    current_node->next = to_add;
    return ;
}

void add_log(const char *msg)
// Create a log_chain node with the log message and add it to the chain
{
    struct log_chain *entry = kmalloc(sizeof(*entry), GFP_KERNEL);
    if (!entry)
        return;

    entry->log = kstrdup(msg, GFP_KERNEL);
    if (!entry->log) {
        kfree(entry);
        return;
    }
    push_back_logs(entry);
    entry->next = NULL;
}


void free_logs(void)
{
    struct log_chain *current_node = logs_list_head;
    struct log_chain *next;

    while (current_node)
    {
        next = current_node->next;
        kfree(current_node->log);
        kfree(current_node);
        current_node = next;
    }
    logs_list_head = NULL;
}
