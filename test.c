#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/list.h>
#include <linux/string.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Toi");
MODULE_DESCRIPTION("Exemple simple de parser/tokenizer dans un module kernel");

// === Structures ===
typedef struct s_token {
    char *value;
    int type;
    struct list_head list;
} t_token;

typedef struct s_command {
    struct list_head tokens;
    struct list_head list;
} t_command;

// === Liste principale de commandes ===
static LIST_HEAD(commands_list);

// === Fonction de découpage en tokens ===
static void tokenize_line(const char *line)
{
    char *copy, *token, *rest;
    t_command *cmd;
    t_token *tok;

    copy = kstrdup(line, GFP_KERNEL);
    if (!copy)
        return;

    // Nouvelle commande
    cmd = kmalloc(sizeof(t_command), GFP_KERNEL);
    if (!cmd) {
        kfree(copy);
        return;
    }
    INIT_LIST_HEAD(&cmd->tokens);
    list_add_tail(&cmd->list, &commands_list);

    rest = copy;
    while ((token = strsep(&rest, " \t\n")) != NULL) {
        if (*token == '\0') // ignorer les vides
            continue;

        tok = kmalloc(sizeof(t_token), GFP_KERNEL);
        if (!tok)
            continue;

        tok->value = kstrdup(token, GFP_KERNEL);
        tok->type = 0; // type dummy
        INIT_LIST_HEAD(&tok->list);
        list_add_tail(&tok->list, &cmd->tokens);
    }

    kfree(copy);
}

// === Affichage des commandes ===
static void print_commands(void)
{
    t_command *cmd;
    t_token *tok;

    list_for_each_entry(cmd, &commands_list, list) {
        printk(KERN_INFO "[cmd] Nouvelle commande :\n");
        list_for_each_entry(tok, &cmd->tokens, list) {
            printk(KERN_INFO "  -> Token: %s\n", tok->value);
        }
    }
}

// === Libération mémoire ===
static void free_commands(void)
{
    t_command *cmd, *tmp_cmd;
    t_token *tok, *tmp_tok;

    list_for_each_entry_safe(cmd, tmp_cmd, &commands_list, list) {
        list_for_each_entry_safe(tok, tmp_tok, &cmd->tokens, list) {
            list_del(&tok->list);
            kfree(tok->value);
            kfree(tok);
        }
        list_del(&cmd->list);
        kfree(cmd);
    }
}

// === Init / Exit ===
static int __init parser_init(void)
{
    printk(KERN_INFO "[parser] Module chargé\n");
    tokenize_line("ls -la /tmp");
    print_commands();
    return 0;
}

static void __exit parser_exit(void)
{
    free_commands();
    printk(KERN_INFO "[parser] Module déchargé\n");
}

module_init(parser_init);
module_exit(parser_exit);
