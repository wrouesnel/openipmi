/*
 * ipmi_payload.c
 *
 * MontaVista IPMI code for handling IPMI-specific data formatting
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004 MontaVista Software Inc.
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

#include <string.h>

#include <OpenIPMI/ipmi_lan.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_addr.h>
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_debug.h>
#include <OpenIPMI/internal/ipmi_int.h>

#if defined(DEBUG_MSG) || defined(DEBUG_RAWMSG)
static void
dump_hex(void *vdata, int len)
{
    unsigned char *data = vdata;
    int i;
    for (i=0; i<len; i++) {
	if ((i != 0) && ((i % 16) == 0)) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n  ");
	}
	ipmi_log(IPMI_LOG_DEBUG_CONT, " %2.2x", data[i]);
    }
}
#endif

static unsigned char
ipmb_checksum(unsigned char *data, int size)
{
	unsigned char csum = 0;
	
	for (; size > 0; size--, data++)
		csum += *data;

	return -csum;
}

static int
ipmi_format_msg(ipmi_con_t        *ipmi,
		const ipmi_addr_t *addr,
		unsigned int      addr_len,
		const ipmi_msg_t  *msg,
		unsigned char     *out_data,
		unsigned int      *out_data_len,
		int               *out_of_session,
		unsigned char     seq)
{
    unsigned char *tmsg = out_data;
    int           pos;
    int           msgstart;

    if (addr->addr_type == IPMI_SYSTEM_INTERFACE_ADDR_TYPE) {
	/* It's a message straight to the BMC. */
	ipmi_system_interface_addr_t *si_addr
	    = (ipmi_system_interface_addr_t *) addr;

	if ((unsigned int) (msg->data_len + 7) > *out_data_len)
	    return E2BIG;
	if (ipmi->hacks & IPMI_CONN_HACK_20_AS_MAIN_ADDR)
	    tmsg[0] = 0x20;
	else
	    tmsg[0] = ipmi->ipmb_addr[0]; /* To the BMC. */
	tmsg[1] = (msg->netfn << 2) | si_addr->lun;
	tmsg[2] = ipmb_checksum(tmsg, 2);
	tmsg[3] = 0x81; /* Remote console IPMI Software ID */
	tmsg[4] = seq << 2;
	tmsg[5] = msg->cmd;
	memcpy(tmsg+6, msg->data, msg->data_len);
	pos = msg->data_len + 6;
	tmsg[pos] = ipmb_checksum(tmsg+3, pos-3);
	pos++;
    } else {
	/* It's an IPMB address, route it using a send message
           command. */
	ipmi_ipmb_addr_t *ipmb_addr = (ipmi_ipmb_addr_t *) addr;
	int              do_broadcast = 0;

	if (ipmb_addr->channel >= MAX_IPMI_USED_CHANNELS)
	    return EINVAL;

	if ((addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)
	    && (!ipmi->broadcast_broken))
	{
	    do_broadcast = 1;
	}

	if ((unsigned int) (msg->data_len + 15 + do_broadcast) > *out_data_len)
	    return E2BIG;

	pos = 0;
	if (ipmi->hacks & IPMI_CONN_HACK_20_AS_MAIN_ADDR)
	    tmsg[pos++] = 0x20;
	else
	    tmsg[pos++] = ipmi->ipmb_addr[0]; /* BMC is the bridge. */
	tmsg[pos++] = (IPMI_APP_NETFN << 2) | 0;
	tmsg[pos++] = ipmb_checksum(tmsg, 2);
	tmsg[pos++] = 0x81; /* Remote console IPMI Software ID */
	tmsg[pos++] = (seq << 2) | 0; /* LUN is zero */
	tmsg[pos++] = IPMI_SEND_MSG_CMD;
	tmsg[pos++] = ((ipmb_addr->channel & 0xf)
		       | (1 << 6)); /* Turn on tracking. */
	if (do_broadcast)
	    tmsg[pos++] = 0; /* Do a broadcast. */
	msgstart = pos;
	tmsg[pos++] = ipmb_addr->slave_addr;
	tmsg[pos++] = (msg->netfn << 2) | ipmb_addr->lun;
	tmsg[pos++] = ipmb_checksum(tmsg+msgstart, 2);
	msgstart = pos;
	tmsg[pos++] = ipmi->ipmb_addr[ipmb_addr->channel];
	tmsg[pos++] = (seq << 2) | 2; /* add 2 as the SMS LUN */
	tmsg[pos++] = msg->cmd;
	memcpy(tmsg+pos, msg->data, msg->data_len);
	pos += msg->data_len;
	tmsg[pos] = ipmb_checksum(tmsg+msgstart, pos-msgstart);
	pos++;
	tmsg[pos] = ipmb_checksum(tmsg+3, pos-3);
	pos++;
    }

    *out_data_len = pos;
    return 0;
}

static int
ipmi_get_recv_seq(ipmi_con_t    *ipmi,
		  unsigned char *data,
		  unsigned int  data_len,
		  unsigned char *seq)
{
    if (data_len < 8) { /* Minimum size of an IPMI msg. */
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "Dropped message because too small(6)");
	return EINVAL;
    }

    if ((data[5] == IPMI_READ_EVENT_MSG_BUFFER_CMD)
	&& ((data[1] >> 2) == (IPMI_APP_NETFN | 1)))
    {
	/* An async event has no seq #, handle async. */
	return ENOSYS;
    }

    *seq = data[4] >> 2;
    return 0;
}

static int
ipmi_handle_recv(ipmi_con_t    *ipmi,
		 ipmi_msgi_t   *rspi,
		 ipmi_addr_t   *orig_addr,
		 unsigned int  orig_addr_len,
		 ipmi_msg_t    *orig_msg,
		 unsigned char *data,
		 unsigned int  data_len)
{
    ipmi_msg_t    *msg = &(rspi->msg);
    ipmi_addr_t   *addr = &(rspi->addr);
    ipmi_addr_t   addr2;
    unsigned int  addr_len;
    unsigned int  seq;
    unsigned char *tmsg = data;
    int           chan;
    int           to_ret = 0;

    if (data_len < 8) { /* Minimum size of an IPMI msg. */
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG,
		     "Dropped message because too small(6)");
	return EINVAL;
    }

    /* We don't check the checksums, because the network layer should
       validate all this for us. */

    seq = data[4] >> 2;

    if ((orig_addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)
	|| (orig_addr->addr_type == IPMI_IPMB_ADDR_TYPE))
    {
	ipmi_ipmb_addr_t *ipmb2 = (ipmi_ipmb_addr_t *) orig_addr;
	chan = ipmb2->channel;
    } else
	chan = 0;

    if ((tmsg[5] == IPMI_SEND_MSG_CMD)
	&& ((tmsg[1] >> 2) == (IPMI_APP_NETFN | 1)))
    {
	/* It's a response to a sent message. */
	ipmi_ipmb_addr_t *ipmb_addr = (ipmi_ipmb_addr_t *) addr;
	ipmi_ipmb_addr_t *ipmb2 = (ipmi_ipmb_addr_t *) orig_addr;

	/* FIXME - this entire thing is a cheap hack. */
	if (tmsg[6] != 0) {
	    /* Got an error from the send message.  We don't have any
               IPMB information to work with, so just extract it from
               the original message. */
	    memcpy(ipmb_addr, ipmb2, sizeof(*ipmb_addr));
	    /* Just in case it's a broadcast. */
	    ipmb_addr->addr_type = IPMI_IPMB_ADDR_TYPE;
	    addr_len = sizeof(ipmi_ipmb_addr_t);
	    msg->netfn = orig_msg->netfn | 1;
	    msg->cmd = orig_msg->cmd;
	    msg->data = tmsg + 6;
	    msg->data_len = 1;
	    to_ret = -1;
	} else {
	    if (data_len < 15)
		/* The response to a send message was not carrying the
		   payload. */
		return EINVAL;

	    if ((orig_msg->cmd == IPMI_SEND_MSG_CMD)
		&& (orig_msg->netfn == IPMI_APP_NETFN))
	    {
		/* Boy, I hate IPMI message routing.  If the original
		   command from the user was a send message, then
		   assume this was the response the user was looking
		   for.  This means that you can't route send message
		   responses through a connection that supports
		   returning the message data in the send message
		   response, but that's wrong, anyway. */
		goto handle_normal_msg;
	    }

	    if (tmsg[10] == ipmi->ipmb_addr[chan]) {
		ipmi_system_interface_addr_t *si_addr
		    = (ipmi_system_interface_addr_t *) addr;

		/* It's directly from the BMC, so it's a system interface
		   message. */
		si_addr->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
		si_addr->channel = 0xf;
		si_addr->lun = tmsg[11] & 3;
	    } else {
		/* This is a hack, but the channel does not come back in the
		   message.  So we use the channel from the original
		   instead. */
		ipmb_addr->addr_type = IPMI_IPMB_ADDR_TYPE;
		ipmb_addr->channel = ipmb2->channel;
		ipmb_addr->slave_addr = tmsg[10];
		ipmb_addr->lun = tmsg[11] & 0x3;
	    }
	    msg->netfn = tmsg[8] >> 2;
	    msg->cmd = tmsg[12];
	    addr_len = sizeof(ipmi_ipmb_addr_t);
	    msg->data = tmsg+13;
	    msg->data_len = data_len - 15;
	}
    } else {
    handle_normal_msg:
	if ((orig_addr->addr_type != IPMI_SYSTEM_INTERFACE_ADDR_TYPE)
	    && (((ipmi->hacks & IPMI_CONN_HACK_20_AS_MAIN_ADDR)
		 && (tmsg[3] == 0x20))
		|| ((! (ipmi->hacks & IPMI_CONN_HACK_20_AS_MAIN_ADDR))
		    && ((tmsg[3] == ipmi->ipmb_addr[chan])
			/* Some systems don't swap rq and rs addresses :( */
			|| ((tmsg[3] == 0x81)
			    && (tmsg[0] == ipmi->ipmb_addr[chan]))))))
	{
	    /* In some cases, a message from the IPMB looks like it came
	       from the BMC itself, IMHO a misinterpretation of the
	       errata.  IPMIv1_5_rev1_1_0926 markup, section 6.12.4,
	       didn't clear things up at all.  Some manufacturers have
	       interpreted it this way, but IMHO it is incorrect. */
	    /* That said, this is the way things are.  This appears to be
	       the correct interpretation of the spec, even though it's
	       crazy. */
	    memcpy(addr, orig_addr, orig_addr_len);
	    addr_len = orig_addr_len;
	    if (addr->addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)
		addr->addr_type = IPMI_IPMB_ADDR_TYPE;
	    msg->netfn = tmsg[1] >> 2;
	    msg->cmd = tmsg[5];
	    msg->data = tmsg+6;
	    msg->data_len = data_len - 7;
	} else {
	    /* It's not encapsulated in a send message response. */

	    if (((ipmi->hacks & IPMI_CONN_HACK_20_AS_MAIN_ADDR)
		 && (tmsg[3] == 0x20))
		|| ((!(ipmi->hacks & IPMI_CONN_HACK_20_AS_MAIN_ADDR))
		    && ((tmsg[3] == ipmi->ipmb_addr[chan])
			/* Some systems don't swap rq and rs addresses :( */
			|| ((tmsg[3] == 0x81)
			    && (tmsg[0] == ipmi->ipmb_addr[chan])))))
	    {
		ipmi_system_interface_addr_t *si_addr
		    = (ipmi_system_interface_addr_t *) addr;

		/* It's directly from the BMC, so it's a system interface
		   message. */
		si_addr->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
		si_addr->channel = 0xf;
		si_addr->lun = tmsg[4] & 3;
	    } else {
		ipmi_ipmb_addr_t *ipmb_addr	= (ipmi_ipmb_addr_t *) addr;
		ipmi_ipmb_addr_t *ipmb2 = (ipmi_ipmb_addr_t *) orig_addr;

		/* A message from the IPMB. */
		ipmb_addr->addr_type = IPMI_IPMB_ADDR_TYPE;
		/* This is a hack, but the channel does not come
		   back in the message.  So we use the channel
		   from the original instead. */
		ipmb_addr->channel = ipmb2->channel;
		ipmb_addr->slave_addr = tmsg[3];
		ipmb_addr->lun = tmsg[4] & 0x3;
	    }

	    msg->netfn = tmsg[1] >> 2;
	    msg->cmd = tmsg[5];
	    addr_len = sizeof(ipmi_system_interface_addr_t);
	    msg->data = tmsg+6;
	    msg->data_len = data_len - 6;
	    msg->data_len--; /* Remove the checksum */
	}
    }
    
    /* Convert broadcast addresses to regular IPMB addresses, since
       they come back that way. */
    memcpy(&addr2, orig_addr, orig_addr_len);
    if (addr2.addr_type == IPMI_IPMB_BROADCAST_ADDR_TYPE)
	addr2.addr_type = IPMI_IPMB_ADDR_TYPE;

    /* Validate that this response is for this command. */
    if (((orig_msg->netfn | 1) != msg->netfn)
	|| (orig_msg->cmd != msg->cmd)
	|| (! ipmi_addr_equal(&addr2, orig_addr_len, addr, addr_len)))
    {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR) {
	    ipmi_log(IPMI_LOG_DEBUG_START,
                     "Dropped message seq %d - netfn/cmd/addr mismatch\n"
                     " netfn     = %2.2x, exp netfn = %2.2x\n"
                     " cmd       = %2.2x, exp cmd   = %2.2x\n"
                     " addr      =",
                     seq,
		     msg->netfn, orig_msg->netfn | 1,
		     msg->cmd, orig_msg->cmd);
	    dump_hex(addr, addr_len);
	    ipmi_log(IPMI_LOG_DEBUG_CONT,
		     "\n exp addr=");
	    dump_hex(&addr2, orig_addr_len);
	    if (data_len) {
		ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data     =\n  ");
		dump_hex(tmsg, data_len);
	    }
	    dump_hex(addr, addr_len);
            ipmi_log(IPMI_LOG_DEBUG_END, " ");
	}
	return EINVAL;
    }

    rspi->addr_len = addr_len;
    memcpy(rspi->data, msg->data, msg->data_len);
    msg->data = rspi->data;

    if (DEBUG_MSG) {
	char buf1[32], buf2[32], buf3[32];
        ipmi_log(IPMI_LOG_DEBUG_START, "incoming msg from IPMB addr =");
        dump_hex((unsigned char *) addr, addr_len);
        ipmi_log(IPMI_LOG_DEBUG_CONT,
                "\n msg  = netfn=%s cmd=%s data_len=%d. cc=%s",
		ipmi_get_netfn_string(msg->netfn, buf1, 32),
                ipmi_get_command_string(msg->netfn, msg->cmd, buf2, 32),
		 msg->data_len,
		ipmi_get_cc_string(msg->data[0], buf3, 32));
	if (msg->data_len) {
	    ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data =\n  ");
	    dump_hex(msg->data, msg->data_len);
	}
        ipmi_log(IPMI_LOG_DEBUG_END, " ");
    }

    return to_ret;
}

static void
ipmi_handle_recv_async(ipmi_con_t    *ipmi,
		       unsigned char *tmsg,
		       unsigned int  data_len)
{
    ipmi_addr_t  addr;
    unsigned int addr_len;
    ipmi_msg_t   msg;

    if ((tmsg[5] == IPMI_READ_EVENT_MSG_BUFFER_CMD)
	&& ((tmsg[1] >> 2) == (IPMI_APP_NETFN | 1)))
    {
	/* It is an event from the event buffer. */
	ipmi_system_interface_addr_t *si_addr
	    = (ipmi_system_interface_addr_t *) &addr;

	if (tmsg[6] != 0) {
	    /* An error getting the events, just ignore it. */
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Dropped message err getting event");
	    return;
	}

	si_addr->addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si_addr->channel = 0xf;
	si_addr->lun = tmsg[4] & 3;

	msg.netfn = tmsg[1] >> 2;
	msg.cmd = tmsg[5];
	addr_len = sizeof(ipmi_system_interface_addr_t);
	msg.data = tmsg+6;
	msg.data_len = data_len - 6;
        if (DEBUG_MSG) {
	    char buf1[32], buf2[32], buf3[32];
	    ipmi_log(IPMI_LOG_DEBUG_START, "incoming async event\n addr =");
	    dump_hex((unsigned char *) &addr, addr_len);
            ipmi_log(IPMI_LOG_DEBUG_CONT,
		     "\n msg  = netfn=%s cmd=%s data_len=%d. cc=%s",
		     ipmi_get_netfn_string(msg.netfn, buf1, 32),
		     ipmi_get_command_string(msg.netfn, msg.cmd, buf2, 32),
		     msg.data_len,
		     ipmi_get_cc_string(msg.data[0], buf3, 32));
	    if (msg.data_len) {
		ipmi_log(IPMI_LOG_DEBUG_CONT, "\n data(len=%d.) =\n  ",
			 msg.data_len);
		dump_hex(msg.data, msg.data_len);
	    }
	    ipmi_log(IPMI_LOG_DEBUG_END, " ");
        }
	if (ipmi->handle_async_event)
	    ipmi->handle_async_event(ipmi, &addr, addr_len, &msg);
    } else {
	ipmi_log(IPMI_LOG_SEVERE, "ipmi_lan.c(ipmi_handle_recv_async): "
		 "Got an invalid async event, shouldn't happen");
    }
}

ipmi_payload_t _ipmi_payload =
{ ipmi_format_msg, ipmi_get_recv_seq, ipmi_handle_recv,
  ipmi_handle_recv_async };
