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
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_event.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_conn.h>

/* Don't pollute the namespace iwth ipmi_fru_t. */
void ipmi_cmdlang_dump_fru_info(ipmi_cmd_info_t *cmd_info, ipmi_fru_t *fru);

static void
domain_list_handler(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
}

static void
domain_list(ipmi_cmd_info_t *cmd_info)
{
    ipmi_domain_iterate_domains(domain_list_handler, cmd_info);
}

static void
domain_info(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    ipmi_cmdlang_out(cmd_info, "Domain", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
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

void
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

    if (!rv)
	/* If we get an error removing the connect change handler,
	   that means this has already been done. */
	ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
domain_new(ipmi_cmd_info_t *cmd_info)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    ipmi_args_t    *con_parms[2];
    int            set = 0;
    int            i;
    ipmi_con_t     *con[2];
    int            rv;
    char           *name;
    int            curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int            argc = ipmi_cmdlang_get_argc(cmd_info);
    char           **argv = ipmi_cmdlang_get_argv(cmd_info);
    int            num_options = 0;
    ipmi_open_option_t options[10];

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
	if (strcmp(argv[curr_arg], "-noall") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_ALL;
	    options[num_options].ival = 0;
	} else if (strcmp(argv[curr_arg], "-all") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_ALL;
	    options[num_options].ival = 1;
	} else if (strcmp(argv[curr_arg], "-nosdrs") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_SDRS;
	    options[num_options].ival = 0;
	} else if (strcmp(argv[curr_arg], "-sdrs") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_SDRS;
	    options[num_options].ival = 1;
	} else if (strcmp(argv[curr_arg], "-nofrus") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_FRUS;
	    options[num_options].ival = 0;
	} else if (strcmp(argv[curr_arg], "-frus") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_FRUS;
	    options[num_options].ival = 1;
	} else if (strcmp(argv[curr_arg], "-nosel") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_FRUS;
	    options[num_options].ival = 0;
	} else if (strcmp(argv[curr_arg], "-sel") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_FRUS;
	    options[num_options].ival = 1;
	} else if (strcmp(argv[curr_arg], "-noipmbscan") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_IPMB_SCAN;
	    options[num_options].ival = 0;
	} else if (strcmp(argv[curr_arg], "-ipmbscan") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_IPMB_SCAN;
	    options[num_options].ival = 1;
	} else if (strcmp(argv[curr_arg], "-nooeminit") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_OEM_INIT;
	    options[num_options].ival = 0;
	} else if (strcmp(argv[curr_arg], "-oeminit") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_OEM_INIT;
	    options[num_options].ival = 1;
	} else if (strcmp(argv[curr_arg], "-noseteventrcvr") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_SET_EVENT_RCVR;
	    options[num_options].ival = 0;
	} else if (strcmp(argv[curr_arg], "-seteventrcvr") == 0) {
	    options[num_options].option = IPMI_OPEN_OPTION_SET_EVENT_RCVR;
	    options[num_options].ival = 1;
	}
	num_options++;
	curr_arg++;
    }

    rv = ipmi_parse_args(&curr_arg, argc, argv, &con_parms[set]);
    if (rv) {
	cmdlang->errstr = "First connection parms are invalid";
	cmdlang->err = rv;
	goto out;
    }
    set++;

    if (curr_arg > argc) {
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
				 cmdlang->selector,
				 &con[i]);
	if (rv) {
	    cmdlang->errstr = "Unable to setup connection";
	    cmdlang->err = rv;
	    for (i=0; i<set; i++)
		ipmi_free_args(con_parms[i]);
	    goto out;
	}
    }

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_open_domain(name, con, set, domain_new_done,
			  cmd_info, options, num_options, NULL);
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
domain_fru_fetched(ipmi_fru_t *fru, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);

    ipmi_cmdlang_lock(cmd_info);

    if (err) {
	ipmi_domain_t *domain = ipmi_fru_get_domain(fru);

	cmdlang->errstr = "Error fetching FRU info";
	cmdlang->err = err;
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_fru_fetched)";
	goto out;
    }

    ipmi_cmdlang_dump_fru_info(cmd_info, fru);

 out:
    ipmi_cmdlang_unlock(cmd_info);
    if (err != ECANCELED)
	ipmi_fru_destroy(fru, NULL, NULL);
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
    rv = ipmi_fru_alloc(domain,
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
    char             domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

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
	ipmi_cmdlang_out_binary(cmd_info, "Data", msg->data, msg->data_len);
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

    if (! cmdlang->err) {
	if (err) {
	    ipmi_cmdlang_lock(cmd_info);
	    cmdlang->err = err;
	    cmdlang->errstr = "Error scanning domain";
	    ipmi_domain_get_name(domain, cmdlang->objstr,
				 cmdlang->objstr_len);
	    cmdlang->location = "cmd_domain.c(scan_done)";
	    ipmi_cmdlang_unlock(cmd_info);
	}
    }
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
domain_presence(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    rv = ipmi_detect_domain_presence_changes(domain, 1);
    if (rv) {
	cmdlang->err = rv;
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_presence)";
    }
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

    ipmi_domain_set_ipmb_rescan_time(domain, time);

 out_err:
    if (cmdlang->err) {
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_ipmb_rescan_time)";
    }
}

static void
final_close(void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
domain_close(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_close_connection(domain, final_close, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->err = rv;
	ipmi_domain_get_name(domain, cmdlang->objstr,
			     cmdlang->objstr_len);
	cmdlang->location = "cmd_domain.c(domain_close)";
    }
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

    ipmi_cmdlang_event_out(event, evi);

 out_err:
    if (rv) {
	char domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

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
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));

    evi = ipmi_cmdlang_alloc_event_info();
    if (!evi) {
	rv = ENOMEM;
	errstr = "Out of memory";
	goto out_err;
    }

    ipmi_cmdlang_out(evi, "Object Type", "Domain");
    ipmi_cmdlang_out(evi, "Operation", "Connection Change");
    ipmi_cmdlang_out(evi, "Name", domain_name);
    ipmi_cmdlang_out_int(evi, "Connection Number", conn_num);
    ipmi_cmdlang_out_int(evi, "Port Number", port_num);
    ipmi_cmdlang_out_int(evi, "Any Connection Up", still_connected);
    ipmi_cmdlang_out_int(evi, "Error", err);

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
    char            domain_name[IPMI_MAX_DOMAIN_NAME_LEN];

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
	ipmi_cmdlang_global_err(domain_name, "cmd_domain.c(domain_new_done)",
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

    ipmi_cmdlang_out(cmd_info, "Object Type", "Event");
    ipmi_cmdlang_out(cmd_info, "MC", mc_name);
    ipmi_cmdlang_out_int(cmd_info, "Record ID",
			 ipmi_event_get_record_id(event));
    ipmi_cmdlang_out_int(cmd_info, "Event type", ipmi_event_get_type(event));
    ipmi_cmdlang_out_long(cmd_info, "Timestamp",
			  (long) ipmi_event_get_timestamp(event));
    len = ipmi_event_get_data_len(event);
    if (len) {
	ipmi_cmdlang_out_binary(cmd_info, "Data",
				ipmi_event_get_data_ptr(event), len);
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
      "[<options>] <domain parms> - Set up a new domain.  Options enable"
      " and disable various automitic processing and are: "
      " -[no]all - all automatic handling, -[no]sdrs - sdr fetching,"
      " -[no]frus - FRU fetching, -[no]sel - SEL fetching,"
      " -[no]ipmbscan - IPMB bus scanning,"
      " -[no]oeminit - special OEM processing (like ATCA),"
      " -[no]seteventrcvr - setting event receivers.",
      domain_new, NULL, NULL },
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
      " for all SELs in the system.  zero disables scans.",
      ipmi_cmdlang_domain_handler, domain_sel_rescan_time, NULL },
    { "ipmb_rescan_time", &domain_cmds,
      "<domain> <time in seconds> - Set the time between IPMB rescans"
      " for this domain.  zero disables scans.",
      ipmi_cmdlang_domain_handler, domain_ipmb_rescan_time, NULL },
};
#define CMDS_DOMAIN_LEN (sizeof(cmds_domain)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_domain_init(void)
{
    int rv;

    rv = ipmi_domain_add_domain_change_handler(domain_change, NULL);
    if (rv)
	return rv;

    return ipmi_cmdlang_reg_table(cmds_domain, CMDS_DOMAIN_LEN);
}
