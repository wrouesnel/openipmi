/*
 * cmd_domain.c
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

#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_conn.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_malloc.h>

/* Don't pollute the namespace iwth ipmi_fru_t. */
void ipmi_cmdlang_dump_fru_info(ipmi_cmd_info_t *cmd_info, ipmi_fru_t *fru);

static void
domain_list_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            domain_name[IPMI_DOMAIN_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
}

static void
domain_list(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_out(cmd_info, "Domains", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_domain_iterate_domains(domain_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
domain_info(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            domain_name[IPMI_DOMAIN_NAME_LEN];
    unsigned char   guid[16];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    ipmi_cmdlang_out(cmd_info, "Domain", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
    if (ipmi_domain_get_guid(domain, guid) == 0)
	ipmi_cmdlang_out_binary(cmd_info, "GUID", (char *) guid, 16);
    ipmi_cmdlang_out(cmd_info, "Type",
		    ipmi_domain_get_type_string(ipmi_domain_get_type(domain)));
    ipmi_cmdlang_out_int(cmd_info, "SEL Rescan Time",
			 ipmi_domain_get_sel_rescan_time(domain));
    ipmi_cmdlang_out_int(cmd_info, "IPMB Rescan Time",
			 ipmi_domain_get_ipmb_rescan_time(domain));
    ipmi_cmdlang_up(cmd_info);
}

static void domain_con_change(ipmi_domain_t *domain,
			      int           err,
			      unsigned int  conn_num,
			      unsigned int  port_num,
			      int           still_connected,
			      void          *cb_data);
void ipmi_cmdlang_entity_change(enum ipmi_update_e op,
				ipmi_domain_t      *domain,
				ipmi_entity_t      *entity,
				void               *cb_data);
void ipmi_cmdlang_mc_change(enum ipmi_update_e op,
			    ipmi_domain_t      *domain,
			    ipmi_mc_t          *mc,
			    void               *cb_data);

static void
domain_new_done(ipmi_domain_t *domain,
		int           err,
		unsigned int  conn_num,
		unsigned int  port_num,
		int           still_connected,
		void          *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    int             rv;


    /* This call will detect and ignore duplicates, no special
       handling required. */
    ipmi_domain_add_connect_change_handler(domain, domain_con_change, NULL);

    /* Remove ourselves from the connection change list.  This may fail,
       but that means it's already been done and we don't care. */
    rv = ipmi_domain_remove_connect_change_handler(domain, domain_new_done,
						   cb_data);


    /* Handle the rest as a normal event. */
    domain_con_change(domain, err, conn_num, port_num, still_connected,
		      NULL);

    /* If we get an error removing the connect change handler,
       that means this has already been done. */
    if ((!rv) && cmd_info) {
	char  domain_name[IPMI_DOMAIN_NAME_LEN];

	ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
	ipmi_cmdlang_lock(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Domain Created", domain_name);
	ipmi_cmdlang_unlock(cmd_info);
	ipmi_cmdlang_cmd_info_put(cmd_info);
    }
}

void
domain_fully_up(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            *errstr = NULL;
    int             rv = 0;
    ipmi_cmd_info_t *evi;
    char            domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Domain");
    ipmi_cmdlang_out(evi, "Domain", domain_name);
    ipmi_cmdlang_out(evi, "Operation", "Domain fully up");

 out_err:
    if (rv) {
	ipmi_cmdlang_global_err(domain_name,
				"cmd_domain.c(domain_fully_up)",
				errstr, rv);
    }
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);

    if (cmd_info) {
	ipmi_cmdlang_lock(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Domain Created", domain_name);
	ipmi_cmdlang_unlock(cmd_info);
	ipmi_cmdlang_cmd_info_put(cmd_info);
    }
}

static void
domain_new(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    ipmi_args_t    *con_parms[2];
    int            set = 0;
    int            i, j;
    ipmi_con_t     *con[2];
    int            rv;
    char           *name;
    int            curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int            argc = ipmi_cmdlang_get_argc(cmd_info);
    char           **argv = ipmi_cmdlang_get_argv(cmd_info);
    int            num_options = 0;
    ipmi_open_option_t options[10];
    int            wait_til_up = 0;
    void           *up_info = NULL;
    void           *con_info = NULL;

    if (curr_arg >= argc) {
	cmdlang->errstr = "No domain name entered";
	cmdlang->err = EINVAL;
	goto out;
    }
    name = argv[curr_arg];
    curr_arg++;

    while ((curr_arg < argc) && argv[curr_arg][0] == '-') {
	if (num_options >= 10) {
	    cmdlang->errstr = "Too many options";
	    cmdlang->err = EINVAL;
	    goto out;
	}

	if (! ipmi_parse_options(options+num_options, argv[curr_arg]))
	    num_options++;
	else if (strcmp(argv[curr_arg], "-wait_til_up") == 0)
	    wait_til_up = 1;
	else
	    break;
	curr_arg++;
    }

    rv = ipmi_parse_args(&curr_arg, argc, argv, &con_parms[set]);
    if (rv) {
	cmdlang->errstr = "First connection parms are invalid";
	cmdlang->err = rv;
	goto out;
    }
    set++;

    if (curr_arg < argc) {
	rv = ipmi_parse_args(&curr_arg, argc, argv, &con_parms[set]);
	if (rv) {
	    ipmi_free_args(con_parms[0]);
	    cmdlang->errstr = "Second connection parms are invalid";
	    cmdlang->err = rv;
	    goto out;
	}
	set++;
    }

    for (i=0; i<set; i++) {
	rv = ipmi_args_setup_con(con_parms[i],
				 cmdlang->os_hnd,
				 NULL,
				 &con[i]);
	if (rv) {
	    cmdlang->errstr = "Unable to setup connection";
	    cmdlang->err = rv;
	    for (j=0; j<set; j++)
		ipmi_free_args(con_parms[j]);
	    goto out;
	}
    }

    if (wait_til_up)
	up_info = cmd_info;
    else
	con_info = cmd_info;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_open_domain(name, con, set, domain_new_done, con_info,
			  domain_fully_up, up_info,
			  options, num_options, NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = strerror(rv);
	cmdlang->err = rv;
	for (i=0; i<set; i++) {
	    ipmi_free_args(con_parms[i]);
	    con[i]->close_connection(con[i]);
	}
	goto out;
    }

    for (i=0; i<set; i++)
      ipmi_free_args(con_parms[i]);

 out:
    if (cmdlang->err)
	cmdlang->location = "cmd_domain.c(domain_new)";

    return;
}


static void
domain_open(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    ipmi_args_t    *con_parms[2];
    int            set = 0;
    int            i, j;
    ipmi_con_t     *con[2];
    int            rv;
    char           *name;
    int            curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int            argc = ipmi_cmdlang_get_argc(cmd_info);
    char           **argv = ipmi_cmdlang_get_argv(cmd_info);
    int            num_options = 0;
    ipmi_open_option_t options[10];
    int            wait_til_up = 0;
    void           *up_info = NULL;
    void           *con_info = NULL;

    if (curr_arg >= argc) {
	cmdlang->errstr = "No domain name entered";
	cmdlang->err = EINVAL;
	goto out;
    }
    name = argv[curr_arg];
    curr_arg++;

    while ((curr_arg < argc) && argv[curr_arg][0] == '-') {
	if (num_options >= 10) {
	    cmdlang->errstr = "Too many options";
	    cmdlang->err = EINVAL;
	    goto out;
	}

	if (! ipmi_parse_options(options+num_options, argv[curr_arg]))
	    num_options++;
	else if (strcmp(argv[curr_arg], "-wait_til_up") == 0)
	    wait_til_up = 1;
	else
	    break;
	curr_arg++;
    }

    rv = ipmi_parse_args2(&curr_arg, argc, argv, &con_parms[set]);
    if (rv) {
	cmdlang->errstr = "First connection parms are invalid";
	cmdlang->err = rv;
	goto out;
    }
    set++;

    if (curr_arg < argc) {
	rv = ipmi_parse_args2(&curr_arg, argc, argv, &con_parms[set]);
	if (rv) {
	    ipmi_free_args(con_parms[0]);
	    cmdlang->errstr = "Second connection parms are invalid";
	    cmdlang->err = rv;
	    goto out;
	}
	set++;
    }

    for (i=0; i<set; i++) {
	rv = ipmi_args_setup_con(con_parms[i],
				 cmdlang->os_hnd,
				 NULL,
				 &con[i]);
	if (rv) {
	    cmdlang->errstr = "Unable to setup connection";
	    cmdlang->err = rv;
	    for (j=0; j<i; j++)
		con[j]->close_connection(con[j]);
	    for (j=0; j<set; j++)
		ipmi_free_args(con_parms[j]);
	    goto out;
	}
    }

    if (wait_til_up)
	up_info = cmd_info;
    else
	con_info = cmd_info;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_open_domain(name, con, set, domain_new_done, con_info,
			  domain_fully_up, up_info,
			  options, num_options, NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = strerror(rv);
	cmdlang->err = rv;
	for (i=0; i<set; i++) {
	    ipmi_free_args(con_parms[i]);
	    con[i]->close_connection(con[i]);
	}
	goto out;
    }

    for (i=0; i<set; i++)
      ipmi_free_args(con_parms[i]);

 out:
    if (cmdlang->err)
	cmdlang->location = "cmd_domain.c(domain_open)";

    return;
}

void con_usage(const char *name, const char *help, void *cb_data)
{
    ipmi_cmdlang_t *cmdlang = cb_data;

    cmdlang->out(cmdlang, name, help);
}

static void
domain_open_help(ipmi_cmdlang_t *cmdlang)
{
    ipmi_parse_args_iter_help(con_usage, cmdlang);
    cmdlang->out(cmdlang, "Options are:\n", ipmi_parse_options_help());
}

static void
domain_fru_fetched(ipmi_domain_t *domain, ipmi_fru_t *fru,
		   int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);

    if (err && (ipmi_fru_get_data_length(fru) == 0)) {
	cmdlang->errstr = "Error fetching FRU info";
	cmdlang->err = err;
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_fru_fetched)";
	goto out;
    }

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Domain", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
    if (err)
	ipmi_cmdlang_out_int(cmd_info, "Warning fetching FRU", err);
    ipmi_cmdlang_dump_fru_info(cmd_info, fru);
    ipmi_cmdlang_up(cmd_info);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
domain_fru(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             is_logical;
    int             device_addr;
    int             device_id;
    int             lun;
    int             private_bus;
    int             channel;
    int             rv;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);

    if ((argc - curr_arg) < 6) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_bool(argv[curr_arg], &is_logical, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "is_logical invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &device_addr, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "device_address invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &device_id, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "device_id invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &lun, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "lun invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &private_bus, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "private_bus invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &channel, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "channel invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_domain_fru_alloc(domain,
			       is_logical,
			       device_addr,
			       device_id,
			       lun,
			       private_bus,
			       channel,
			       domain_fru_fetched,
			       cmd_info,
			       NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error allocating FRU info";
	cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    ipmi_domain_get_name(domain, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_domain.c(domain_fru)";
}

static int
domain_msg_handler(ipmi_domain_t *domain, ipmi_msgi_t *rspi)
{
    ipmi_msg_t       *msg = &rspi->msg;
    ipmi_ipmb_addr_t *addr = (ipmi_ipmb_addr_t *) &rspi->addr;
    ipmi_cmd_info_t  *cmd_info = rspi->data1;
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Response", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Domain", domain_name);
    ipmi_cmdlang_out_int(cmd_info, "channel", addr->channel);
    ipmi_cmdlang_out_hex(cmd_info, "ipmb", addr->slave_addr);
    ipmi_cmdlang_out_int(cmd_info, "LUN", addr->lun);
    ipmi_cmdlang_out_int(cmd_info, "NetFN", msg->netfn);
    ipmi_cmdlang_out_int(cmd_info, "command", msg->cmd);
    if (msg->data_len)
	ipmi_cmdlang_out_binary(cmd_info, "Data",
				(char *) msg->data, msg->data_len);
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_up(cmd_info);

    ipmi_cmdlang_cmd_info_put(cmd_info);

    return IPMI_MSG_ITEM_NOT_USED;
}

static void
domain_msg(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t  *cmd_info = cb_data;
    ipmi_cmdlang_t   *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int              channel;
    int              ipmb;
    int              is_broadcast = 0;
    int              LUN;
    int              NetFN;
    int              command;
    unsigned char    data[100];
    int              rv;
    int              i;
    ipmi_ipmb_addr_t addr;
    ipmi_msg_t       msg;
    int              curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int              argc = ipmi_cmdlang_get_argc(cmd_info);
    char             **argv = ipmi_cmdlang_get_argv(cmd_info);


    if ((argc - curr_arg) < 5) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &channel, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "channel invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &ipmb, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "ipmb invalid";
	goto out_err;
    }
    curr_arg++;

    if (ipmb == 0) {
	is_broadcast = 1;
	if ((argc - curr_arg) < 5) {
	    /* Not enough parameters */
	    cmdlang->errstr = "Not enough parameters";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	ipmi_cmdlang_get_int(argv[curr_arg], &ipmb, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "ipmb invalid";
	    goto out_err;
	}
	curr_arg++;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &LUN, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "LUN invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &NetFN, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "NetFN invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &command, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "command invalid";
	goto out_err;
    }
    curr_arg++;

    i = 0;
    while (curr_arg < argc) {
	ipmi_cmdlang_get_uchar(argv[curr_arg], &data[i], cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "data invalid";
	    goto out_err;
	}
	curr_arg++;
	i++;
    }

    if (is_broadcast)
	addr.addr_type = IPMI_IPMB_BROADCAST_ADDR_TYPE;
    else
	addr.addr_type = IPMI_IPMB_ADDR_TYPE;
    addr.channel = channel;
    addr.slave_addr = ipmb;
    addr.lun = LUN;
    msg.netfn = NetFN;
    msg.cmd = command;
    msg.data_len = i;
    msg.data = data;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_send_command_addr(domain,
				(ipmi_addr_t *) &(addr),
				sizeof(addr),
				&msg,
				domain_msg_handler,
				cmd_info, NULL);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error sending message";
	cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    if (cmdlang->err) {
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_msg)";
    }
}

static void
scan_done(ipmi_domain_t *domain, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	if (! cmdlang->err) {
	    cmdlang->err = err;
	    cmdlang->errstr = "Error scanning domain";
	    ipmi_domain_get_name(domain, cmdlang->objstr,
				 cmdlang->objstr_len);
	    cmdlang->location = "cmd_domain.c(scan_done)";
	}
	goto out;
    }

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Scan done", domain_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
domain_scan(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    int             channel;
    int             ipmb1, ipmb2;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);

    if ((argc - curr_arg) < 2) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &channel, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "channel invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &ipmb1, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "ipmb1 invalid";
	goto out_err;
    }
    curr_arg++;

    if (curr_arg < argc) {
	ipmi_cmdlang_get_int(argv[curr_arg], &ipmb2, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "ipmb2 invalid";
	    goto out_err;
	}
	curr_arg++;
    } else
	ipmb2 = ipmb1;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_start_ipmb_mc_scan(domain, channel, ipmb1, ipmb2,
				 scan_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error requesting scan";
	cmdlang->err = rv;
	goto out_err;
    }
    
 out_err:
    if (cmdlang->err) {
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_scan)";
    }
}

static void
domain_rescan_sels_done(ipmi_domain_t *domain, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_cmdlang_lock(cmd_info);
    if (err) {
	if (! cmdlang->err) {
	    cmdlang->err = err;
	    cmdlang->errstr = "Error scanning SELs";
	    ipmi_domain_get_name(domain, cmdlang->objstr,
				 cmdlang->objstr_len);
	    cmdlang->location = "cmd_domain.c(sel_rescan_done)";
	}
	goto out;
    }

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "SEL Rescan done", domain_name);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
domain_rescan_sels(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_domain_reread_sels(domain, domain_rescan_sels_done, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Error requesting SEL rescan";
	cmdlang->err = rv;
	goto out_err;
    }
    
 out_err:
    if (cmdlang->err) {
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_rescan_sels)";
    }
}

static void
domain_presence(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    rv = ipmi_detect_domain_presence_changes(domain, 1);
    if (rv) {
	cmdlang->err = rv;
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_presence)";
	goto out;
    }
    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Presence check started", domain_name);
 out:
    return;
}

static void
domain_sel_rescan_time(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             time;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &time, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "time invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_domain_set_sel_rescan_time(domain, time);

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Domain SEL rescan time set", domain_name);

 out_err:
    if (cmdlang->err) {
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_sel_rescan_time)";
    }
}


static void
domain_ipmb_rescan_time(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             time;
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    char            domain_name[IPMI_DOMAIN_NAME_LEN];

    if ((argc - curr_arg) < 1) {
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &time, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "time invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_domain_set_ipmb_rescan_time(domain, time);

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Domain IPMB rescan time set", domain_name);

 out_err:
    if (cmdlang->err) {
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_ipmb_rescan_time)";
    }
}

static void
handle_stat(ipmi_domain_t *domain, ipmi_domain_stat_t *stat, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    const char      *name = ipmi_domain_stat_get_name(stat);
    const char      *inst = ipmi_domain_stat_get_instance(stat);
    char            *s = ipmi_mem_alloc(strlen(name) + strlen(inst) + 2);

    if (!s)
	return;
    sprintf(s, "%s %s", name, inst);
    ipmi_cmdlang_out_int(cmd_info, s, ipmi_domain_stat_get(stat));
    ipmi_mem_free(s);
}

static void
domain_stats(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Domain statistics", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Domain", domain_name);
    ipmi_domain_stat_iterate(domain, NULL, NULL, handle_stat, cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

typedef struct domain_close_info_s
{
    char            domain_name[IPMI_DOMAIN_NAME_LEN];
    ipmi_cmd_info_t *cmd_info;
} domain_close_info_t;

static void
final_close(void *cb_data)
{
    domain_close_info_t *info = cb_data;
    ipmi_cmd_info_t *cmd_info = info->cmd_info;

    ipmi_cmdlang_lock(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Domain closed", info->domain_name);
    ipmi_cmdlang_unlock(cmd_info);

    ipmi_mem_free(info);

    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
domain_close(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t     *cmd_info = cb_data;
    ipmi_cmdlang_t      *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                 rv;
    domain_close_info_t *info = cb_data;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	goto out_err;
    }
    ipmi_domain_get_name(domain, info->domain_name, sizeof(info->domain_name));
    info->cmd_info = cmd_info;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_domain_close(domain, final_close, info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Unable to close domain";
	cmdlang->err = rv;
	goto out_err;
    }
    return;

 out_err:
    ipmi_domain_get_name(domain, cmdlang->objstr,
			 cmdlang->objstr_len);
    cmdlang->location = "cmd_domain.c(domain_close)";
}


/**********************************************************************
 *
 * Domain event handling.
 *
 **********************************************************************/

static void
domain_event_handler(ipmi_domain_t *domain,
		     ipmi_event_t  *event,
		     void          *cb_data)
{
    char            *errstr = NULL;
    int             rv = 0;
    ipmi_cmd_info_t *evi;

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Event");
    ipmi_cmdlang_event_out(event, evi);

 out_err:
    if (rv) {
	char domain_name[IPMI_DOMAIN_NAME_LEN];

	ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
	ipmi_cmdlang_global_err(domain_name,
				"cmd_domain.c(domain_event_handler)",
				errstr, rv);
    }
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

static void
domain_con_change(ipmi_domain_t *domain,
		  int           err,
		  unsigned int  conn_num,
		  unsigned int  port_num,
		  int           still_connected,
		  void          *cb_data)
{
    char            *errstr;
    int             rv = 0;
    ipmi_cmd_info_t *evi;
    char            domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Domain");
    ipmi_cmdlang_out(evi, "Name", domain_name);
    ipmi_cmdlang_out(evi, "Operation", "Connection Change");
    ipmi_cmdlang_out_int(evi, "Connection Number", conn_num);
    ipmi_cmdlang_out_int(evi, "Port Number", port_num);
    ipmi_cmdlang_out_bool(evi, "Any Connection Up", still_connected);
    ipmi_cmdlang_out_int(evi, "Error", err);

    if (err) {
	char errval[128];
	ipmi_cmdlang_out(evi, "Error String",
			 ipmi_get_error_string(err, errval, sizeof(errval)));
	
    }
    errstr = NULL; /* Get rid of warning */

 out_err:
    if (rv) {
	ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
	ipmi_cmdlang_global_err(domain_name, "cmd_domain.c(domain_con_change)",
				errstr, rv);
    }
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

void
domain_change(ipmi_domain_t      *domain,
	      enum ipmi_update_e op,
	      void               *cb_data)
{
    ipmi_cmd_info_t *evi;
    int             rv = 0;
    char            *errstr = NULL;
    char            domain_name[IPMI_DOMAIN_NAME_LEN];

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));


    ipmi_cmdlang_out(evi, "Object Type", "Domain");
    ipmi_cmdlang_out(evi, "Name", domain_name);

    switch (op) {
    case IPMI_ADDED:
	ipmi_cmdlang_out(evi, "Operation", "Add");
	if (ipmi_cmdlang_get_evinfo()) {
	    ipmi_cmdlang_down(evi);
	    domain_info(domain, evi);
	    ipmi_cmdlang_up(evi);
	}
	/* Register handlers. */
	rv = ipmi_domain_add_event_handler(domain, domain_event_handler, NULL);
	if (rv) {
	    errstr = "ipmi_register_for_events";
	    goto out_err;
	}

	rv = ipmi_domain_enable_events(domain);
	if (rv) {
	    errstr = "ipmi_domain_enable_events";
	    goto out_err;
	}

	rv = ipmi_domain_add_entity_update_handler(domain,
						   ipmi_cmdlang_entity_change,
						   domain);
	if (rv) {
	    errstr = "ipmi_bmc_set_entity_update_handler";
	    goto out_err;
	}

	rv = ipmi_domain_add_mc_updated_handler(domain,
						ipmi_cmdlang_mc_change,
						domain);
	if (rv) {
	    errstr = "ipmi_bmc_set_entity_update_handler";
	    goto out_err;
	}
	break;

    case IPMI_DELETED:
	ipmi_cmdlang_out(evi, "Operation", "Delete");
	break;

    default:
	break;
    }

 out_err:
    /* FIXME - should we shut the connection down on errors? */
    if (rv) {
	ipmi_cmdlang_global_err(domain_name, "cmd_domain.c(domain_change)",
				errstr, rv);
    }
    if (evi)
	ipmi_cmdlang_cmd_info_put(evi);
}

static void
get_mc_name(ipmi_mc_t *mc, void *cb_data)
{
    char *mc_name = cb_data;

    ipmi_mc_get_name(mc, mc_name, IPMI_MC_NAME_LEN);
}

void
ipmi_cmdlang_event_out(ipmi_event_t    *event,
		       ipmi_cmd_info_t *cmd_info)
{
    ipmi_mcid_t     mcid;
    char            mc_name[IPMI_MC_NAME_LEN];
    unsigned int    len;
    int             rv;

    mcid = ipmi_event_get_mcid(event);
    rv = ipmi_mc_pointer_cb(mcid, get_mc_name, mc_name);
    if (rv) {
	/* The MC went away, that's actually ok, just ignore it. */
	ipmi_cmdlang_cmd_info_put(cmd_info);
	return;
    }

    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_out_int(cmd_info, "Record ID",
			 ipmi_event_get_record_id(event));
    ipmi_cmdlang_out_int(cmd_info, "Event type", ipmi_event_get_type(event));
    ipmi_cmdlang_out_time(cmd_info, "Timestamp",
			  ipmi_event_get_timestamp(event));
    len = ipmi_event_get_data_len(event);
    if (len) {
	unsigned char *data;
	data = ipmi_mem_alloc(len);
	if (!data)
	    return;
	len = ipmi_event_get_data(event, data, 0, len);
	ipmi_cmdlang_out_binary(cmd_info, "Data", (char *) data, len);
	ipmi_mem_free(data);
    }
}

static ipmi_cmdlang_cmd_t *domain_cmds;

static ipmi_cmdlang_init_t cmds_domain[] =
{
    { "domain", NULL,
      "- Commands dealing with domains",
      NULL, NULL, &domain_cmds},
    { "list", &domain_cmds,
      "- List all the domains in the system",
      domain_list, NULL,  NULL },
    { "info", &domain_cmds,
      "<domain> - Dump information about a domain",
      ipmi_cmdlang_domain_handler, domain_info, NULL },
    { "new", &domain_cmds,
      "Obsolete, use domain open",
      domain_new, NULL, NULL },
    { "open", &domain_cmds,
      "<domain name> [<options>] <domain parms> [<domain parms>]- Set up a"
      " new domain using an argument parser.  Format for the connection's"
      " <domain parms> depends on the connections type.  Two connections"
      " (to two different MCs) can be done by specifying two sets of parms."
      " Connections types are:",
      domain_open, NULL, NULL, domain_open_help },
    { "close", &domain_cmds,
      "<domain> - Close the domain",
      ipmi_cmdlang_domain_handler, domain_close, NULL },
    { "fru", &domain_cmds,
      "<domain> <is_logical> <device_address> <device_id>"
      " <lun> <private_bus> <channel>"
      " - Fetch FRU data with the given parms",
      ipmi_cmdlang_domain_handler, domain_fru, NULL },
    { "msg", &domain_cmds,
      "<domain> <channel> <ipmb> <LUN> <NetFN> <command> [data...]"
      " - Send a message to the given address",
      ipmi_cmdlang_domain_handler, domain_msg, NULL },
    { "scan", &domain_cmds,
      "<domain> <channel> <ipmb addr> [ipmb addr]"
      " - scan an IPMB to add or remove it. If a range is given,"
      " then scan all IPMBs in the range",
      ipmi_cmdlang_domain_handler, domain_scan, NULL },
    { "presence", &domain_cmds,
      "<domain> - Check the presence of all entities in the domain",
      ipmi_cmdlang_domain_handler, domain_presence, NULL },
    { "sel_rescan_time", &domain_cmds,
      "<domain> <time in seconds> - Set the time between SEL rescans"
      " for all SELs in the domain.  Zero disables scans.",
      ipmi_cmdlang_domain_handler, domain_sel_rescan_time, NULL },
    { "rescan_sels", &domain_cmds,
      "<domain> - Rescan all the SELs in the domain",
      ipmi_cmdlang_domain_handler, domain_rescan_sels, NULL },
    { "ipmb_rescan_time", &domain_cmds,
      "<domain> <time in seconds> - Set the time between IPMB rescans"
      " for this domain.  zero disables scans.",
      ipmi_cmdlang_domain_handler, domain_ipmb_rescan_time, NULL },
    { "stats", &domain_cmds,
      "<domain> - Dump all the domain's statistics",
      ipmi_cmdlang_domain_handler, domain_stats, NULL },
};
#define CMDS_DOMAIN_LEN (sizeof(cmds_domain)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_domain_init(os_handler_t *os_hnd)
{
    int rv;

    rv = ipmi_domain_add_domain_change_handler(domain_change, NULL);
    if (rv)
	return rv;

    return ipmi_cmdlang_reg_table(cmds_domain, CMDS_DOMAIN_LEN);
}
