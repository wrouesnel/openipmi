/*
 * lanserv_config.c
 *
 * MontaVista IPMI code for reading lanserv configuration files.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004,2005 MontaVista Software Inc.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * Lesser General Public License (GPL) Version 2 or the modified BSD
 * license below.  The following disclamer applies to both licenses:
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
 * GNU Lesser General Public Licence
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Modified BSD Licence
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *   3. The name of the author may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 */

#include <config.h>

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/lanserv.h>
#include <OpenIPMI/serserv.h>

#ifndef IPMI_LAN_STD_PORT_STR
#define IPMI_LAN_STD_PORT_STR	"623"
#endif

int
lanserv_read_config(sys_data_t    *sys,
		    FILE          *f,
		    int           *line,
		    unsigned int  channel_num)
{
    char         buf[MAX_CONFIG_LINE];
    const char   *tok;
    char         *tokptr;
    unsigned int val;
    int          err = 0;
    const char   *errstr;
    lanserv_data_t *lan;


    lan = sys->alloc(sys, sizeof(*lan));
    if (!lan) {
	err = -1;
	errstr = "Out of memory allocating lan data";
	goto out_err;
    }
    memset(lan, 0, sizeof(*lan));

    lan->sysinfo = sys;
    lan->channel.chan_info = lan;
    lan->channel.channel_num = channel_num;
    lan->channel.medium_type = IPMI_CHANNEL_MEDIUM_8023_LAN;
    lan->channel.protocol_type = IPMI_CHANNEL_PROTOCOL_IPMB;
    lan->channel.session_support = IPMI_CHANNEL_MULTI_SESSION;
    lan->users = sys->cusers;

    if (sys->chan_set[channel_num]) {
	err = -1;
	errstr = "Channel already in use";
	goto out_err;
    }

    while (fgets(buf, sizeof(buf), f) != NULL) {
	(*line)++;

	tok = mystrtok(buf, " \t\n", &tokptr);
	if (!tok || (tok[0] == '#'))
	    continue;

	if (strcmp(tok, "endlan") == 0) {
	    sys->chan_set[channel_num] = &lan->channel;
	    return 0;
	}

	if (strcmp(tok, "PEF_alerting") == 0) {
	    err = get_bool(&tokptr, &val, &errstr);
	    lan->channel.PEF_alerting = val;
	} else if (strcmp(tok, "per_msg_auth") == 0) {
	    err = get_bool(&tokptr, &val, &errstr);
	    lan->channel.per_msg_auth = val;
	} else if (strcmp(tok, "priv_limit") == 0) {
	    err = get_priv(&tokptr, &val, &errstr);
	    lan->channel.privilege_limit = val;
	} else if (strcmp(tok, "allowed_auths_callback") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[0].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_user") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[1].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_operator") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[2].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_admin") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[3].allowed_auths = val;
	} else if (strcmp(tok, "addr") == 0) {
	    if (lan->lan_addr_set) {
		fprintf(stderr, "LAN address already set, line %d\n", *line);
		return -1;
	    }
	    err = get_sock_addr(&tokptr, &lan->lan_addr.addr,
				&lan->lan_addr.addr_len,
				IPMI_LAN_STD_PORT_STR, SOCK_DGRAM, &errstr);
	    lan->lan_addr_set = 1;
	    if (!err) {
		if (lan->lan_addr.addr.s_ipsock.s_addr.sa_family == AF_INET)
		    lan->port = lan->lan_addr.addr.s_ipsock.s_addr4.sin_port;
		else if (lan->lan_addr.addr.s_ipsock.s_addr.sa_family == AF_INET6)
		    lan->port = lan->lan_addr.addr.s_ipsock.s_addr6.sin6_port;
		else
		    lan->port = 0;
		lan->port = htons(lan->port);
	    }
	} else if (strcmp(tok, "guid") == 0) {
	    if (!lan->guid)
		lan->guid = malloc(16);
	    if (!lan->guid)
		return -1;
	    err = read_bytes(&tokptr, lan->guid, &errstr, 16);
	    if (err)
		goto out_err;
	} else if (strcmp(tok, "bmc_key") == 0) {
	    if (!lan->bmc_key)
		lan->bmc_key = malloc(20);
	    if (!lan->bmc_key)
		return -1;
	    err = read_bytes(&tokptr, lan->bmc_key, &errstr, 20);
	    if (err)
		goto out_err;
	} else if (strcmp(tok, "lan_config_program") == 0) {
	    err = get_delim_str(&tokptr, &lan->config_prog, &errstr);
	    if (err)
		goto out_err;
	} else {
	    errstr = "Invalid configuration option";
	    err = -1;
	}

	if (err) {
	out_err:
	    sys->free(sys, lan);
	    fprintf(stderr, "Error on line %d: %s\n", *line, errstr);
	    return err;
	}
    }

    sys->free(sys, lan);
    fprintf(stderr, "End of file in lan section\n");
    return -1;
}
