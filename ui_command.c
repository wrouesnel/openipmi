
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <string.h>
#include "ui_command.h"

static int search_cmd(void *item, void *cb_data)
{
    struct cmd_entry *entry = item;
    char             *val = cb_data;

    return (strcmp(entry->name, val) == 0);
}

static struct cmd_entry *
find_cmd(ilist_iter_t *iter, command_t command, char *name)
{
    struct cmd_entry *entry;

    ilist_init_iter(iter, command->cmds);
    ilist_unpositioned(iter);
    entry = ilist_search_iter(iter, search_cmd, name);
    return entry;
}

int
command_handle(command_t command, char *line, void *cb_data)
{
    ilist_iter_t     iter;
    struct cmd_entry *entry;
    char             *name;
    char             *tok;

    name = strtok_r(line, " \t\n", &tok);
    if (!name)
	return 0;

    entry = find_cmd(&iter, command, name);
    if (!entry)
	return ENOENT;

    return entry->handler(name, &tok, cb_data);
}

int
command_bind(command_t command, char *name, cmd_handler_t handler)
{
    ilist_iter_t     iter;
    struct cmd_entry *entry;

    if (find_cmd(&iter, command, name))
	return EEXIST;

    entry = malloc(sizeof(*entry));
    if (!entry)
	return ENOMEM;

    entry->name = strdup(name);
    if (!entry->name) {
	free(entry);
	return ENOMEM;
    }
    entry->handler = handler;
    if (!ilist_add_tail(command->cmds, entry, NULL)) {
	free(entry->name);
	free(entry);
	return ENOMEM;
    }

    return 0;
}

int
command_unbind(command_t command, char *name)
{
    ilist_iter_t     iter;
    struct cmd_entry *entry;

    entry = find_cmd(&iter, command, name);
    if (!entry)
	return ENOENT;

    ilist_delete(&iter);
    free(entry->name);
    free(entry);
    return 0;
}

command_t
command_alloc(void)
{
    command_t command = malloc(sizeof(*command));

    if (command) {
	command->cmds = alloc_ilist();
	if (!command->cmds) {
	    free(command);
	    command = NULL;
	}
    }

    return command;
}

static void
free_cmd_entry(ilist_iter_t *iter, void *item, void *cb_data)
{
    struct cmd_entry *entry = item;
    ilist_delete(iter);
    free(entry->name);
    free(entry);
}

void
command_free(command_t command)
{
    ilist_iter(command->cmds, free_cmd_entry, NULL);
    free_ilist(command->cmds);
    free(command);
}
