#include "../includes/L3SM.h"

bool rule_check_access(kuid_t uid, kgid_t gid, pid_t pid, int mask, const char *path)
{
    if (!path)
        return false;

    struct rule_node *curr = rule_list_head;
    char uid_buf[16], gid_buf[16], pid_buf[16];

    snprintf(uid_buf, sizeof(uid_buf), "%u", __kuid_val(uid));
    snprintf(gid_buf, sizeof(gid_buf), "%u", __kgid_val(gid));
    snprintf(pid_buf, sizeof(pid_buf), "%d", pid);

    while (curr)
    {
        rule_t *rule = &curr->rule;
        if (rule->path && strcmp(rule->path, path) != 0)
        {
            curr = curr->next;
            continue;
        }
        if (rule->uid && strlen(rule->uid) > 0 && strcmp(rule->uid, uid_buf) != 0)
        {
            curr = curr->next;
            continue;
        }
        if (rule->gid && strlen(rule->gid) > 0 && strcmp(rule->gid, gid_buf) != 0)
        {
            curr = curr->next;
            continue;
        }
        if (rule->pid && strlen(rule->pid) > 0 && strcmp(rule->pid, pid_buf) != 0)
        {
            curr = curr->next;
            continue;
        }
        if (rule->right && strchr(rule->right, 'N'))
            return true;
        if (rule->right && strlen(rule->right) > 0)
        {
            bool restriction = false;

            if ((mask & L3SM_RIGHT_READ)  && !strchr(rule->right, 'R'))
                restriction = true;
            if ((mask & L3SM_RIGHT_WRITE) && !strchr(rule->right, 'W'))
                restriction = true;
            if ((mask & L3SM_RIGHT_EXEC)  && !strchr(rule->right, 'X'))
                restriction = true;
            if ((mask & L3SM_RIGHT_MOOV)  && !strchr(rule->right, 'M'))
                restriction = true;

            if (restriction)
                return true;
        }
        curr = curr->next;
    }

    return (false);
}

