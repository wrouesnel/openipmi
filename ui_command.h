
#ifndef UI_COMMAND_H
#define UI_COMMAND_H

#include "ilist.h"

typedef int (*cmd_handler_t)(char *cmd, char **toks, void *cb_data);

struct cmd_entry {
    char          *name;
    cmd_handler_t handler;
};

typedef struct {
    ilist_t *cmds;
} *command_t;

int command_handle(command_t command, char *line, void *cb_data);
int command_bind(command_t command, char *name, cmd_handler_t handler);
int command_unbind(command_t command, char *name);
command_t command_alloc(void);
void command_free(command_t command);

#endif /* UI_COMMAND_H */
