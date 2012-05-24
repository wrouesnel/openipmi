/*
 * emu.h
 *
 * MontaVista IPMI LAN server include file
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003,2004,2005,2012 MontaVista Software Inc.
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

#ifndef __IPMI_SIM_MSG_
#define __IPMI_SIM_MSG_

#include <stdint.h>

typedef struct msg_s
{
    void *src_addr;
    int  src_len;

    long oem_data; /* For use by OEM handlers.  This will be set to
                      zero by the calling code. */

    unsigned char channel;

    unsigned char authtype;
    uint32_t      seq;
    uint32_t      sid;

    /* RMCP parms */
    unsigned char *authcode;
    unsigned char authcode_data[16];

    /* RMCP+ parms */
    unsigned char payload;
    unsigned char encrypted;
    unsigned char authenticated;
    unsigned char iana[3];
    uint16_t      payload_id;
    unsigned char *authdata;
    unsigned int  authdata_len;

    unsigned char netfn;
    unsigned char rs_addr;
    unsigned char rs_lun;
    unsigned char rq_addr;
    unsigned char rq_lun;
    unsigned char rq_seq;
    unsigned char cmd;

    unsigned char *data;
    unsigned int  len;

    unsigned long ll_data; /* For use by the low-level code. */
} msg_t;

#define IPMI_MAX_CHANNELS 16
#define NUM_PRIV_LEVEL 4
typedef struct channel_s
{
    unsigned char medium_type;
    unsigned char protocol_type;
    unsigned char session_support;

    unsigned int PEF_alerting : 1;
    unsigned int PEF_alerting_nonv : 1;
    unsigned int per_msg_auth : 1;

    /* We don't support user-level authentication disable, and access
       mode is always available and cannot be set. */

    unsigned int privilege_limit : 4;
    unsigned int privilege_limit_nonv : 4;

#define MAX_SESSIONS 63
    unsigned int active_sessions : 6;

    struct {
	unsigned char allowed_auths;
    } priv_info[NUM_PRIV_LEVEL];
} channel_t;

typedef struct user_s
{
    unsigned char valid;
    unsigned char link_auth;
    unsigned char cb_only;
    unsigned char username[16];
    unsigned char pw[20];
    unsigned char privilege;
    unsigned char max_sessions;
    unsigned char curr_sessions;
    uint16_t      allowed_auths;

    /* Set by the user code. */
    int           idx; /* My idx in the table. */
} user_t;

/*
 * Restrictions: <=64 users (per spec, 6 bits)
 */
#define MAX_USERS		63
#define USER_BITS_REQ		6 /* Bits required to hold a user. */
#define USER_MASK		0x3f

/*
 * Generic data about the BMC that is global for the whole BMC and
 * required for all server types.
 */
typedef struct bmc_data_s {
    /* user 0 is not used. */
    user_t users[MAX_USERS + 1];

    channel_t *channels[IPMI_MAX_CHANNELS];
} bmc_data_t;

static inline void
zero_extend_ascii(uint8_t *c, unsigned int len)
{
    unsigned int i;

    i = 0;
    while ((i < len) && (*c != 0)) {
	c++;
	i++;
    }
    while (i < len) {
	*c = 0;
	c++;
	i++;
    }
}

#endif /* __IPMI_SIM_MSG_ */

