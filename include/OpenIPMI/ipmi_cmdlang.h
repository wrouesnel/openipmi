/*
 * ipmi_cmdlang.h
 *
 * A command interpreter for OpenIPMI
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004 MontaVista Software Inc.
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

#ifndef __IPMI_CMDLANG_H
#define __IPMI_CMDLANG_H

#include <OpenIPMI/selector.h>

/* Forward declaration */
typedef struct ipmi_cmd_info_s ipmi_cmd_info_t;

/*
 * A structure that must be passed into the command parser; it has
 * general information about the how the parser should handle thing
 * and generate its output.
 */
typedef struct ipmi_cmdlang_s ipmi_cmdlang_t;

/* Output is done in name:value pairs.  If you don't have a value,
   pass in NULL. */
typedef void (*cmd_out_cb)(ipmi_cmdlang_t *info, char *name, char *value);

/* Command-specific info. */
typedef void (*cmd_info_cb)(ipmi_cmdlang_t *info);

struct ipmi_cmdlang_s
{
    cmd_out_cb   out;	   /* Generate output with this. */
    cmd_info_cb  down;     /* Go down a level (new indention or
			      nesting) */
    cmd_info_cb  up;       /* Go up a level (leave the current
			      indention or nesting) */
    cmd_info_cb  done;     /* Called when the command is done.  If
			      there was an error, the err value in
			      info will be non-null. */

    /* OS handler and selector to use for the commands */
    os_handler_t *os_hnd;
    selector_t   *selector;

    int          err;      /* If non-zero, the errno code of the error
			      that occurred. */
    char         *errstr;  /* If non-NULL, an error occurred and this
			      is the error info. */

    void         *user_data; /* User data for anything the user wants */
};

/* Parse and handle the given command string.  This always calls the
   done function when complete. */
void ipmi_cmdlang_handle(ipmi_cmdlang_t *cmdlang, char *str);


/*
 * This is used to hold command information.
 */
typedef struct ipmi_cmdlang_cmd_s ipmi_cmdlang_cmd_t;

typedef void (*ipmi_cmdlang_handler_cb)(ipmi_cmd_info_t *cmd_info);

/* Register a command as a subcommand of the parent, or into the main
   command list if parent is NULL.  The command will have the given
   name and help text.  When the command is executed, the handler will
   be called with a cmd_info structure passed in.  The handler_data parm
   passed in below will be in the "handler_data" field of the cmd_info
   structure.  Note that if you are attaching subcommands to this
   command, you should pass in a NULL handler.  Returns an error value. */
int ipmi_cmdlang_reg_cmd(ipmi_cmdlang_cmd_t      *parent,
			 char                    *name,
			 char                    *help,
			 ipmi_cmdlang_handler_cb handler,
			 void                    *handler_data,
			 ipmi_cmdlang_cmd_t      **rv);

/* The following functions handle parsing various OpenIPMI objects
   according to the naming standard.  If you pass it into a command
   registration as the handler and pass your function as the
   handler_data, your function will be called with the specified
   object.  The specific function type is given in the individual
   functions.  The cmd_info will be passed in as the cb_data.

   For instance, if you have a command that take an entity argument,
   then you could write:
     void ent_cmd_hnd(ipmi_entity_t *entity, void *cb_data)
     {
         ipmi_cmd_info_t *cmd_info = cb_data;
     }

     rv = ipmi_cmdlang_reg_cmd(parent, "ent_cmd", "The ent command",
			       ipmi_cmdlang_entity_handler, ent_cmd_hnd,
			       &cmd);
*/

/* ipmi_domain_ptr_cb */
void ipmi_cmdlang_domain_handler(ipmi_cmd_info_t *cmd_info);

/* ipmi_entity_ptr_cb */
void ipmi_cmdlang_entity_handler(ipmi_cmd_info_t *cmd_info);

/* ipmi_sensor_ptr_cb */
void ipmi_cmdlang_sensor_handler(ipmi_cmd_info_t *cmd_info);

/* ipmi_control_ptr_cb */
void ipmi_cmdlang_control_handler(ipmi_cmd_info_t *cmd_info);

/* ipmi_mc_ptr_cb */
void ipmi_cmdlang_mc_handler(ipmi_cmd_info_t *cmd_info);

/* ipmi_connection_ptr_cb */
void ipmi_cmdlang_connection_handler(ipmi_cmd_info_t *cmd_info);


/*
 * This is the value passed to a command handler.
 */
struct ipmi_cmd_info_s
{
    void               *handler_data; /* From cb_data in the cmd reg */
    int                curr_arg;      /* Argument you should start at */
    int                argc;          /* Total number of arguments */
    char               **argv;        /* The arguments */
    ipmi_cmdlang_t     *cmdlang;      /* The cmdlang structure to use */
    ipmi_cmdlang_cmd_t *cmd;          /* The matching cmd structure. */

    unsigned int       usecount;

    /* For use by the user commands */
    void *data;
};


void ipmi_cmdlang_out(ipmi_cmd_info_t *info,
		      char            *name,
		      char            *value);
void ipmi_cmdlang_out_int(ipmi_cmd_info_t *info,
			  char            *name,
			  int             value);
void ipmi_cmdlang_out_hex(ipmi_cmd_info_t *info,
			  char            *name,
			  int             value);
void ipmi_cmdlang_down(ipmi_cmd_info_t *info);
void ipmi_cmdlang_up(ipmi_cmd_info_t *info);
void ipmi_cmdlang_cmd_info_get(ipmi_cmd_info_t *info);
void ipmi_cmdlang_cmd_info_put(ipmi_cmd_info_t *info);


int ipmi_cmdlang_init(void);
void ipmi_cmdlang_cleanup(void);

#endif /* __IPMI_CMDLANG_H */
