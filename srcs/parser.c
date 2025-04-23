#include "../includes/L3SM.h"


char *extract_value(const char *input)
{
    const char *start = strchr(input, '\"');
    if (!start)
        return (NULL);

    const char *end = strchr(start + 1, '\"');
    if (!end)
        return (NULL);
    size_t len = end - start - 1;
    char *value = kmalloc(len + 1, GFP_KERNEL);
    if (!value)
        return (NULL);
    strncpy(value, start + 1, len);
    value[len] = '\0';
    return (value);
}

cmd_type_t get_cmd_type(const char *line)
{
    if (strncmp(line, "ADD", 3) == 0)
        return (CMD_ADD);
    if (strncmp(line, "REMOVE", 6) == 0)
        return (CMD_REMOVE);
    if (strncmp(line, "DISPLAY", 7) == 0)
        return (CMD_DISPLAY);
    if (strncmp(line, "SWITCH", 6) == 0)
        return (CMD_SWITCH);
    return (CMD_UNKNOWN);
}

void parse_arguments(parsed_cmd_t *cmd, const char *args)
{
    char *token, *p;

    char *copy = kstrdup(args, GFP_KERNEL);
    if (!copy)
        return;
    p = copy;
    while ((token = strsep(&p, ";")) != NULL)
    {
        while (*token == ' ')
            token++;
        if (strncmp(token, "PATH(", 5) == 0)
            cmd->rule.path = extract_value(token);
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

int empty_rules(const rule_t tocheck)
{
    if (!tocheck.path || !tocheck.right)
        return (1);
    if (!tocheck.uid && !tocheck.user && !tocheck.gid && !tocheck.pid)
        return (1);
    return (0);
}

parsed_cmd_t parse_line(const char *line)
{
    char *args, *start, *end;

    parsed_cmd_t cmd = {0};
    cmd.type = get_cmd_type(line);
    start = strchr(line, '{');
    end = strrchr(line, '}');
    if (!start || !end)
    {
        cmd.type = CMD_UNKNOWN;
        return (cmd);
    }
    if (start >= end || (start + 1 == end))
        return (cmd);
    args = kmalloc(end - start, GFP_KERNEL);
    if (!args)
        return (cmd);
    strncpy(args, start + 1, end - start - 1);
    args[end - start - 1] = '\0';
    if (cmd.type == CMD_ADD)
    {
        parse_arguments(&cmd, args);
    }
    else if (cmd.type == CMD_SWITCH)
    {
        char *args_copy = kstrdup(args, GFP_KERNEL);
        char *p = args_copy;
        char *first_token = strsep(&p, ";");
        char *second_token = strsep(&p, ";");
        printk(KERN_INFO "FIRST TOKEN = %s || second token= %s \n", first_token, second_token);
        if (first_token && strncmp(first_token, "AS(", 3) == 0)
            cmd.arg1 = extract_value(first_token);
        else
        {
            cmd.arg1 = kstrdup(first_token, GFP_KERNEL);
        }
        if (second_token && strncmp(second_token, "AS(", 3) == 0)
            cmd.arg2 = extract_value(second_token);
        else
            cmd.arg2 = kstrdup(second_token, GFP_KERNEL);
        kfree(args_copy);
    }
    else if (cmd.type == CMD_REMOVE)
    {
        if (strncmp(args, "ALIAS(", 6) == 0)
            cmd.arg1 = extract_value(args);
        else
            cmd.arg1 = kstrdup(args, GFP_KERNEL);
    }
    else if (empty_rules(cmd.rule) || invalid_name(cmd.rule.alias))
    {
        cmd.type = CMD_UNKNOWN;
    }
    kfree(args);
    return (cmd);
}

void free_cmd(parsed_cmd_t *cmd)
{
    kfree(cmd->rule.path);
    kfree(cmd->rule.uid);
    kfree(cmd->rule.user);
    kfree(cmd->rule.gid);
    kfree(cmd->rule.pid);
    kfree(cmd->rule.right);
    kfree(cmd->rule.alias);
    kfree(cmd->arg1);
    kfree(cmd->arg2);
    return ;
}
