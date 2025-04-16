#ifndef L3SM_H
# define L3SM_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>


// -------------- DEFINE -------------

#define PROC_DIR_NAME "L3SM"
#define PROC_FILE_NAME "rules"
#define BUF_SIZE 512


// -------------- STRUCT -------------

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


// ------------PARSER---------------

parsed_cmd_t    parse_line(const char *line);
void            free_cmd(parsed_cmd_t *cmd);
char            *extract_value(const char *input);
cmd_type_t      get_cmd_type(const char *line);
void            parse_arguments(parsed_cmd_t *cmd, const char *args);


// --------------LIST---------------

void            add_rule_to_list(rule_t *rule);
void            free_rule_list(void);
void            display_rule_list(void);

extern char rule_buffer[BUF_SIZE];


#endif