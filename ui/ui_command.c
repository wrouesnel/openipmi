/*
 * ui_command.c
 *
 * MontaVista IPMI code, a UI command handler
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *
 *  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 *  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 *  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 *  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
 *  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 *  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
 *  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 *  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */


#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include "ui_command.h"

#include <OpenIPMI/internal/ipmi_malloc.h>

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

    entry = ipmi_mem_alloc(sizeof(*entry));
    if (!entry)
	return ENOMEM;

    entry->name = ipmi_mem_alloc(strlen(name)+1);
    if (!entry->name) {
	ipmi_mem_free(entry);
	return ENOMEM;
    }
    strcpy(entry->name, name);
    entry->handler = handler;
    if (!ilist_add_tail(command->cmds, entry, NULL)) {
	ipmi_mem_free(entry->name);
	ipmi_mem_free(entry);
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
    ipmi_mem_free(entry->name);
    ipmi_mem_free(entry);
    return 0;
}

command_t
command_alloc(void)
{
    command_t command = ipmi_mem_alloc(sizeof(*command));

    if (command) {
	command->cmds = alloc_ilist();
	if (!command->cmds) {
	    ipmi_mem_free(command);
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
    ipmi_mem_free(entry->name);
    ipmi_mem_free(entry);
}

void
command_free(command_t command)
{
    ilist_iter(command->cmds, free_cmd_entry, NULL);
    free_ilist(command->cmds);
    ipmi_mem_free(command);
}
