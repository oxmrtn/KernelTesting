#include "../includes/L3SM.h"


char *extract_value(const char *input)
{
    const char *start = strchr(input, '\"');
    const char *end = strrchr(input, '\"');
    char *value;

    if (!start || !end || start == end)
        return (NULL);
    value = kmalloc(end - start, GFP_KERNEL);
    if (!value)
        return (NULL);
    strncpy(value, start + 1, end - start - 1);
    value[end - start - 1] = '\0';
    return value;
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

parsed_cmd_t parse_line(const char *line)
{
    char *args, *start, *end;

    parsed_cmd_t cmd = {0};
    cmd.type = get_cmd_type(line);
    start = strchr(line, '(');
    end = strrchr(line, ')');
    if (!start || !end || start >= end)
        return (cmd);
    args = kmalloc(end - start, GFP_KERNEL);
    if (!args)
        return (cmd);
    strncpy(args, start + 1, end - start - 1);
    args[end - start - 1] = '\0';
    if (cmd.type == CMD_ADD || cmd.type == CMD_REMOVE)
        parse_arguments(&cmd, args);
    else if (cmd.type == CMD_SWITCH)
    {
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
    return (cmd);
}

void free_cmd(parsed_cmd_t *cmd)
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
    return ;
}
