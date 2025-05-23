#ifndef L3SM_H
# define L3SM_H

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/dcache.h>
#include <linux/path.h>
#include <linux/fs.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/uidgid.h>

// -------------- DEFINE -------------

#define L3SM_RIGHT_READ    MAY_READ
#define L3SM_RIGHT_WRITE   MAY_WRITE
#define L3SM_RIGHT_EXEC    MAY_EXEC
#define L3SM_RIGHT_MOOV    0x10 
#define L3SM_RIGHT_OPEN    0x08

#define PROC_DIR_NAME "L3SM"
#define PROC_FILE_NAME "rules"
#define PROC_FILE_LOG "logs"
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

struct rule_node
{
    rule_t rule;
    struct rule_node *next;
}; 


struct probs_data
{
    bool block;
};

struct log_chain
{
    char *log;
    struct log_chain *next;
};

extern struct log_chain *logs_list_head;

// ------------PARSER---------------

parsed_cmd_t    parse_line(const char *line);
void            free_cmd(parsed_cmd_t *cmd);
int             empty_rules(const rule_t tocheck);
char            *extract_value(const char *input);
cmd_type_t      get_cmd_type(const char *line);
void            parse_arguments(parsed_cmd_t *cmd, const char *args);


// --------------LIST---------------

void            add_rule_to_list(rule_t *rule);
void            free_rule_list(void);
void            display_rule_list(void);
void            switch_rules(int i, int j);
int             find_rule_index_by_alias(const char *alias);
void            remove_rule_by_index(int index);
int             invalid_name(const char *name);


// --------------PROBES-------------
int init_probes(void);
char *get_path(const struct path *path);
int exit_probes(void);


// -------------LOGGER--------------
int log_kern(int pid, char *path);
int log_proc(int pid, char *path);
void free_logs(void);
void add_log(const char *msg);


// ---------- RULE MANAGER ---------
bool rule_check_access(kuid_t uid, kgid_t gid, pid_t pid, int mask, const char *path);

extern char rule_buffer[BUF_SIZE];
extern struct rule_node *rule_list_head;


#endif