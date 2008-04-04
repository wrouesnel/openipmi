/*
 * ipmi_atca_conn.c
 *
 * MontaVista IPMI code for handling ATCA connections
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
#include <stdio.h> /* for snprintf */
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_picmg.h>
#include <OpenIPMI/ipmi_lan.h>

#include <OpenIPMI/internal/ipmi_oem.h>
#include <OpenIPMI/internal/ipmi_int.h>

static unsigned char asf_iana[] = { 0x00, 0x00, 0x11, 0xbe };

/* Because sizeof(sockaddr_in6) > sizeof(sockaddr_in), this structure
 * is used as a replacement of struct sockaddr. */
typedef struct sockaddr_ip_s {
    union
        {
	    struct sockaddr	s_addr;
            struct sockaddr_in  s_addr4;
#ifdef PF_INET6
            struct sockaddr_in6 s_addr6;
#endif
        } s_ipsock;
} sockaddr_ip_t;

static int
lan_addr_same(sockaddr_ip_t *a1, sockaddr_ip_t *a2)
{
    if (a1->s_ipsock.s_addr.sa_family != a2->s_ipsock.s_addr.sa_family) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Address family mismatch: %d %d",
		     a1->s_ipsock.s_addr.sa_family,
		     a2->s_ipsock.s_addr.sa_family);
	return 0;
    }

    switch (a1->s_ipsock.s_addr.sa_family) {
    case PF_INET:
	{
	    struct sockaddr_in *ip1 = &a1->s_ipsock.s_addr4;
	    struct sockaddr_in *ip2 = &a2->s_ipsock.s_addr4;

	    if ((ip1->sin_port == ip2->sin_port)
		&& (ip1->sin_addr.s_addr == ip2->sin_addr.s_addr))
		return 1;
	}
	break;

#ifdef PF_INET6
    case PF_INET6:
	{
	    struct sockaddr_in6 *ip1 = &a1->s_ipsock.s_addr6;
	    struct sockaddr_in6 *ip2 = &a2->s_ipsock.s_addr6;
	    if ((ip1->sin6_port == ip2->sin6_port)
		&& (bcmp(ip1->sin6_addr.s6_addr, ip2->sin6_addr.s6_addr,
			 sizeof(struct in6_addr)) == 0))
		return 1;
	}
	break;
#endif
    default:
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan: Unknown protocol family: 0x%x",
		 a1->s_ipsock.s_addr.sa_family);
	break;
    }

    return 0;
}

typedef struct atca_ip_addr_info_s
{
    /* Usecount for item 0 is for the whole structure.  The usecount
       is protected by the con_change lock in the main LAN code. */
    unsigned int usecount;

    unsigned char site_type;
    unsigned char site_num;
    unsigned char max_unavailable_time;
    unsigned char is_shm;
    unsigned char addr_type;

    unsigned char connected;
    unsigned char found;
    unsigned char changed;
    struct timeval last_pong_time;
    unsigned int  dropped_pings;

    sockaddr_ip_t addr;
    socklen_t     addr_len;
} atca_ip_addr_info_t;

typedef struct atca_conn_info_s
{
    ipmi_con_t          *ipmi;

    ipmi_lock_t         *lock;

    int                 dont_use_floating_addr;
    unsigned int        hacks;

    int                 supports_ip_addr_checking;
    uint32_t            last_ip_change_time;
    unsigned int        num_ip_addr;
    atca_ip_addr_info_t *ip_addrs;
    unsigned int        num_working_ip_addr;
    atca_ip_addr_info_t *working_ip_addrs;
    uint32_t            working_ip_change_time;
    unsigned int        working_ip_addr;

    int (*orig_get_port_info)(ipmi_con_t *ipmi, unsigned int port,
			      char *info, int *info_len);

    unsigned int ipmb_call_count;

    unsigned int hash;
    struct atca_conn_info_s *fd_next;
    struct atca_conn_info_s **fd_list;
} atca_conn_info_t;

static int fd_sock = -1;
static os_hnd_fd_id_t *fd_wait;
static ipmi_lock_t *fd_lock = NULL;
static unsigned int atca_conn_num = 0;
static atca_conn_info_t *fd_hash[255];

static void
fd_sock_handler(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
    sockaddr_ip_t       ipaddrd;
    socklen_t           from_len;
    int                 len;
    unsigned char       data[64];
    atca_conn_info_t    *tinfo;
    unsigned int        count;
    atca_ip_addr_info_t *addrs;

    from_len = sizeof(ipaddrd);
    len = recvfrom(fd, data, sizeof(data), 0, (struct sockaddr *)&ipaddrd, 
		   &from_len);
    if (len < 10)
	/* Got an error, or not enough data, just return. */
	return;

    /* Validate the RMCP portion of the message. */
    if ((data[0] != 6)
	|| (data[2] != 0xff)
	|| (data[3] != 0x06)
	|| (memcmp(data+4, asf_iana, 4) != 0)
	|| (data[8] != 0x40)
	|| (data[9] > 254))
    {
	return;
    }

    ipmi_lock(fd_lock);
    tinfo = fd_hash[data[9]];
    while (tinfo) {
	unsigned int i;

	ipmi_lock(tinfo->lock);
	_ipmi_lan_con_change_lock(tinfo->ipmi);
	for (i=1; i<tinfo->num_ip_addr; i++) {
	    atca_ip_addr_info_t *ainfo = &(tinfo->ip_addrs[i]);
	    if (lan_addr_same(&ainfo->addr, &ipaddrd)) {
		if (!ainfo->connected) {
		    ainfo->connected = 1;
		    ainfo->changed = 1;
		}
		gettimeofday(&ainfo->last_pong_time, NULL);
		ainfo->dropped_pings = 0;
	    }
	}

	addrs = tinfo->ip_addrs;
	addrs[0].usecount++;
	count = tinfo->num_ip_addr;
	ipmi_unlock(tinfo->lock);

	for (i=1; i<count; i++) {
	    atca_ip_addr_info_t *ainfo = &(addrs[i]);
	    if (ainfo->changed) {
		ainfo->changed = 0;
		_ipmi_lan_call_con_change_handlers(tinfo->ipmi, 0, i);
	    }
	}
	_ipmi_lan_con_change_unlock(tinfo->ipmi);

	ipmi_lock(tinfo->lock);
	addrs[0].usecount--;
	if (addrs[0].usecount == 0)
	    ipmi_mem_free(addrs);
	ipmi_unlock(tinfo->lock);

	tinfo = tinfo->fd_next;
    }
    ipmi_unlock(fd_lock);
}

static int register_atca_conn(atca_conn_info_t *info)
{
    int              rv;
    unsigned int     hash;
    os_handler_t     *os_hnd = ipmi_get_global_os_handler();

    ipmi_lock(fd_lock);
    if (fd_sock == -1) {
	fd_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (fd_sock == -1) {
	    rv = errno;
	    goto out_unlock;
	}
	rv = fcntl(fd_sock, F_SETFL, O_NONBLOCK);
	if (rv) {
	    rv = errno;
	    close(fd_sock);
	    fd_sock = -1;
	    goto out_unlock;
	}

	rv = os_hnd->add_fd_to_wait_for(os_hnd,
					fd_sock,
					fd_sock_handler, 
					NULL,
					NULL,
					&fd_wait);
	if (rv) {
	    close(fd_sock);
	    fd_sock = -1;
	    goto out_unlock;
	}
    }

    hash = atca_conn_num;
    atca_conn_num = (atca_conn_num + 1) % 255;
    info->hash = hash;

    info->fd_next = fd_hash[hash];
    info->fd_list = &(fd_hash[hash]);
    fd_hash[hash] = info;

    rv = 0;

 out_unlock:
    ipmi_unlock(fd_lock);
    return rv;
}

static void
atca_decode_addr(atca_ip_addr_info_t *ainfo, ipmi_msg_t *msg)
{
    ainfo->site_type = msg->data[6];
    ainfo->site_num = msg->data[7];
    ainfo->max_unavailable_time = msg->data[8];
    ainfo->is_shm = (msg->data[9] >> 7) & 0x01;
    ainfo->addr_type = msg->data[9] & 0x7f;
    if (ainfo->addr_type == 0) { /* IPV4 addr */
	if (msg->data_len < 16) {
	    ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_decode_addr):"
		     "Invalid length for IPV4 address");
	    
	    goto out;
	}
	ainfo->addr.s_ipsock.s_addr.sa_family = AF_INET;
	memcpy(&ainfo->addr.s_ipsock.s_addr4.sin_addr.s_addr, msg->data+10, 4);
	memcpy(&ainfo->addr.s_ipsock.s_addr4.sin_port, msg->data+14, 2);
	ainfo->addr_len = sizeof(struct sockaddr_in);
    } else {
    out:
	ainfo->addr.s_ipsock.s_addr.sa_family = AF_UNSPEC;
    }
}

static void
atca_check_and_ping(ipmi_con_t *ipmi, atca_conn_info_t *info)
{
    unsigned char  data[12];
    struct timeval now;
    unsigned int   i;

    gettimeofday(&now, NULL);

    data[0] = 0x06; /* RMCP version 1.0 */
    data[1] = 0x00; /* reserved */
    data[2] = 0xff; /* RMCP seq num, not used for IPMI */
    data[3] = 0x06; /* ASF message */
    memcpy(data+4, asf_iana, 4);
    data[8] = 0x80; /* Presence ping */
    data[9] = info->hash; /* Message tag */
    data[10] = 0x00; /* reserved */
    data[11] = 0x00; /* Data length */

    ipmi_lock(info->lock);
    for (i=1; i<info->num_ip_addr; i++) {
	atca_ip_addr_info_t *ainfo = &(info->ip_addrs[i]);

	if (ainfo->connected) {
	    struct timeval t = ainfo->last_pong_time;
	    t.tv_sec += ainfo->max_unavailable_time;
	    if ((t.tv_sec < now.tv_sec) && (ainfo->dropped_pings > 2)) {
		_ipmi_lan_call_con_change_handlers(ipmi, EAGAIN, i);
		ainfo->connected = 0;
	    }
	}

	/* Send a ping. */
	sendto(fd_sock, data, sizeof(data), 0,
	       (struct sockaddr *) &ainfo->addr, ainfo->addr_len);
	ainfo->dropped_pings++;
    }
    ipmi_unlock(info->lock);
}

static void
atca_addr_fetch_done(ipmi_con_t *ipmi, atca_conn_info_t *info, int err)
{
    atca_ip_addr_info_t *c, *w;
    unsigned int        wc, cc;
    unsigned int        i, j;

    if (err) {
	ipmi_mem_free(info->working_ip_addrs);
	info->working_ip_addrs = NULL;
	return;
    }

    ipmi_lock(info->lock);
    c = info->ip_addrs;
    if (c)
	cc = info->num_ip_addr;
    else
	cc = 0;
    w = info->working_ip_addrs;
    wc = info->num_working_ip_addr;
    for (i=1; i<cc; i++)
	c[i].found = 0;
    for (i=1; i<wc; i++) {
	if ((i < cc)
	    && !c[i].found
	    && lan_addr_same(&(c[i].addr), &(w[i].addr)))
	{
	    /* This address is unchanged, so ignore it. */
	    w[i].connected = c[i].connected;
	    w[i].last_pong_time = c[i].last_pong_time;
	    w[i].dropped_pings = c[i].dropped_pings;
	    continue;
	}

	w[i].changed = 1;
	for (j=1; j<cc; j++) {
	    if (!c[j].found
		&& lan_addr_same(&(c[j].addr), &(w[i].addr)))
	    {
		/* Found the same address in a different place. */
		c[j].found = 1;
		w[i].connected = c[j].connected;
		w[i].last_pong_time = c[j].last_pong_time;
		w[i].dropped_pings = c[j].dropped_pings;
	    }
	}
    }

    /* Switch over and report everything that changed. */
    if (info->ip_addrs) {
	(info->ip_addrs[0].usecount)--;
	if (info->ip_addrs[0].usecount == 0)
	    ipmi_mem_free(info->ip_addrs);
    }
    info->ip_addrs = info->working_ip_addrs;
    info->num_ip_addr = info->num_working_ip_addr;
    info->working_ip_addrs = NULL;
    info->last_ip_change_time = info->working_ip_change_time;

    _ipmi_lan_con_change_lock(info->ipmi);
    w[0].usecount++;
    ipmi_unlock(info->lock);

    for (i=1; i<wc; i++) {
	int err = 0;
	if (! w[i].changed)
	    continue;
	w[i].changed = 0;
	if (! w[i].connected)
	    err = EAGAIN;
	_ipmi_lan_call_con_change_handlers(ipmi, err, i);
    }

    for (; i<cc; i++)
	_ipmi_lan_call_con_change_handlers(ipmi, ENOENT, i);
    _ipmi_lan_con_change_unlock(info->ipmi);

    ipmi_lock(info->lock);
    w[0].usecount--;
    if (w[0].usecount == 0)
	ipmi_mem_free(w);
    ipmi_unlock(info->lock);
}

static void atca_fetch_working_addr(ipmi_con_t *ipmi, atca_conn_info_t *info);

static int
atca_oem_ip_next(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t       *msg = &rspi->msg;
    atca_conn_info_t *info;
    int              rv;
    uint32_t         timestamp;

    if (!ipmi)
	return 0;

    info = ipmi->oem_data;
    if (!info)
	goto out;

    if (msg->data[0] != 0) {
	/* Shouldn't give an error, give up for now. */
	rv = IPMI_IPMI_ERR_VAL(msg->data[0]);
	goto out_err;
    }

    if (msg->data_len < 10) {
	ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_oem_ip_next):"
		 "Response is too short: %d", msg->data_len);
	rv = EINVAL;
	goto out_err;
    }

    timestamp = ipmi_get_uint32(msg->data+1);
    if (timestamp != info->working_ip_change_time) {
	/* Value changed, get it on the next try. */
	rv = EAGAIN;
	goto out_err;
    }

    atca_decode_addr(&(info->working_ip_addrs[info->working_ip_addr]), msg);

    info->working_ip_addr++;
    if (info->working_ip_addr >= info->num_working_ip_addr)
	atca_addr_fetch_done(ipmi, info, 0);
    else
	atca_fetch_working_addr(ipmi, info);

 out:
    return IPMI_MSG_ITEM_NOT_USED;

 out_err:
    atca_addr_fetch_done(ipmi, info, rv);
    return IPMI_MSG_ITEM_NOT_USED;
}

static void
atca_fetch_working_addr(ipmi_con_t *ipmi, atca_conn_info_t *info)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char 		 data[2];
    int                          rv;
    ipmi_msgi_t                  *rspi;


    rspi = ipmi_alloc_msg_item();
    if (!rspi) {
	ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_oem_check2):"
		 "Unable to allocate message");
	goto out_err;
    }

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_SHELF_MANAGER_IP_ADDRESSES;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = info->working_ip_addr;
    msg.data = data;
    msg.data_len = 2;

    rv = ipmi->send_command(ipmi, (ipmi_addr_t *) &si, sizeof(si), &msg,
			    atca_oem_ip_next, rspi);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_fetch_working_addr):"
		 "Could not send IP address message");
	ipmi_free_msg_item(rspi);
	atca_addr_fetch_done(ipmi, info, rv);
	goto out_err;
    }

 out_err:
    return;
}

static void
atca_update_ip_addr(atca_conn_info_t *info, ipmi_con_t *ipmi, ipmi_msg_t *msg)
{
    if (info->working_ip_addrs)
	return;

    info->working_ip_change_time = ipmi_get_uint32(msg->data+1);
    if (info->working_ip_change_time == info->last_ip_change_time) {
	atca_check_and_ping(ipmi, info);
	goto out;
    }

    info->working_ip_addrs = ipmi_mem_alloc(sizeof(atca_ip_addr_info_t)
					    * msg->data[5]);
    if (!info->working_ip_addrs) {
	ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_update_ip_addr):"
		 "Could not allocate IP address info");
	goto out;
    }
    memset(info->working_ip_addrs, 0,
	   sizeof(atca_ip_addr_info_t) * msg->data[5]);
    info->working_ip_addrs[0].usecount = 1;

    info->num_working_ip_addr = msg->data[5];
    info->working_ip_addr = 1;

    atca_decode_addr(&(info->working_ip_addrs[0]), msg);

    if (info->num_working_ip_addr <= 1)
	atca_addr_fetch_done(ipmi, info, 0);
    else
	atca_fetch_working_addr(ipmi, info);

 out:
    return;
}

static unsigned int
atca_get_num_ports(ipmi_con_t *ipmi)
{
    atca_conn_info_t *info = ipmi->oem_data;

    return info->num_ip_addr;
}

static int
atca_get_port_info(ipmi_con_t *ipmi, unsigned int port,
		   char *str, int *str_len)
{
    atca_conn_info_t    *info = ipmi->oem_data;
    sockaddr_ip_t       *a;
    int                 count = 0;
    int                 rv = EINVAL;
    int                 len = *str_len;

    if (port == 0)
	return info->orig_get_port_info(ipmi, port, str, str_len);

    ipmi_lock(info->lock);
    if (port > info->num_ip_addr)
	goto out_unlock;

    a = &(info->ip_addrs[port].addr);

    count = snprintf(str, len, "ATCA_aux: ");

    switch (a->s_ipsock.s_addr.sa_family) {
    case PF_INET:
	{
	    struct sockaddr_in *ip = &a->s_ipsock.s_addr4;
	    char buf[INET_ADDRSTRLEN];

	    inet_ntop(AF_INET, &ip->sin_addr, buf, sizeof(buf));
	    count += snprintf(str+count, len-count, "inet:%s:%d",
			      buf, ntohs(ip->sin_port));
	}
	break;

#ifdef PF_INET6
    case PF_INET6:
	{
	    struct sockaddr_in6 *ip = &a->s_ipsock.s_addr6;
	    char buf[INET6_ADDRSTRLEN];

	    inet_ntop(AF_INET6, &ip->sin6_addr, buf, sizeof(buf));
	    count += snprintf(str+count, len-count, "inet6:%s:%d",
			      buf, ntohs(ip->sin6_port));
	}
	break;
#endif
    default:
	count += snprintf(str+count, len-count, "invalid");
	break;
    }
    *str_len = count;
    rv = 0;

 out_unlock:
    ipmi_unlock(info->lock);
    return rv;
}

static int
atca_oem_ip_start(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t       *msg = &rspi->msg;
    atca_conn_info_t *info;
    int              rv;

    if (!ipmi)
	goto out;

    info = ipmi->oem_data;
    if (!info)
	goto out;

    if (msg->data[0] != 0) {
	/* Error checking the IP.  It may have timed out, and we want
	   to go ahead and ping everything even if we have previously
	   determined that address checking works. */
	if (info->supports_ip_addr_checking)
	    atca_check_and_ping(ipmi, info);
	goto out;
    }

    if (msg->data_len < 10) {
	ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_oem_ip_start):"
		 "Response is too short: %d", msg->data_len);
	goto out;
    }

    if (!info->supports_ip_addr_checking) {
	info->supports_ip_addr_checking = 1;

	rv = register_atca_conn(info);
	if (rv) {
	    /* Unable to register, give up. */
	    ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_oem_ip_start):"
		     "Could not register ATCA connection: %x", rv);
	    goto out;
	}

	/* Override the port count. */
	info->num_ip_addr = 1;
	ipmi->get_num_ports = atca_get_num_ports;
	info->orig_get_port_info = ipmi->get_port_info;
	ipmi->get_port_info = atca_get_port_info;
	info->ipmi = ipmi;
    }

    atca_update_ip_addr(info, ipmi, msg);

 out:
    return IPMI_MSG_ITEM_NOT_USED;
}

static void
start_ip_addr_check(ipmi_con_t *ipmi)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char 		 data[2];
    int                          rv;
    ipmi_msgi_t                  *rspi;


    rspi = ipmi_alloc_msg_item();
    if (!rspi) {
	ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_oem_check2):"
		 "Unable to allocate message");
	goto out_err;
    }

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_SHELF_MANAGER_IP_ADDRESSES;
    data[0] = IPMI_PICMG_GRP_EXT;
    data[1] = 0; /* Get address 0. */
    msg.data = data;
    msg.data_len = 2;

    rv = ipmi->send_command(ipmi, (ipmi_addr_t *) &si, sizeof(si), &msg,
			    atca_oem_ip_start, rspi);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_oem_check2):"
		 "Could not send IP address message");
	ipmi_free_msg_item(rspi);
	goto out_err;
    }

 out_err:
    return;
}

static int
atca_ipmb_handler(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t           *msg = &rspi->msg;
    ipmi_ll_ipmb_addr_cb handler = rspi->data1;
    void                 *cb_data = rspi->data2;
    unsigned char        ipmb[MAX_IPMI_USED_CHANNELS];
    int                  err = 0;
    atca_conn_info_t     *info;

    if (!ipmi) {
	if (handler)
	    handler(ipmi, ECANCELED, ipmb, 1, 1, 0, cb_data);
	return IPMI_MSG_ITEM_NOT_USED;
    }

    info = ipmi->oem_data;

    memset(ipmb, 0, sizeof(ipmb));

    if (msg->data[0] != 0) 
	err = IPMI_IPMI_ERR_VAL(msg->data[0]);
    else if (msg->data_len < 4)
	err = EINVAL;
    else if ((msg->data[7] == 3) && (!info->dont_use_floating_addr))
	ipmb[0] = 0x20; /* This is a Dedicated ShMC and we are not doing
			   dual-ShMC addressing. */
    else
	ipmb[0] = msg->data[3];

    /* Note that there is no "inactive" connection with ATCA. */
    if (!err)
	ipmi->set_ipmb_addr(ipmi, ipmb, 1, 1, info->hacks);

    if (handler)
	handler(ipmi, err, ipmb, 1, 1, info->hacks, cb_data);
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
lan_atca_ipmb_fetch(ipmi_con_t           *conn,
		    ipmi_ll_ipmb_addr_cb handler,
		    void                 *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char 		 data[1];
    int                          rv;
    ipmi_msgi_t                  *rspi;
    atca_conn_info_t             *info = conn->oem_data;

    rspi = ipmi_alloc_msg_item();
    if (!rspi)
	return ENOMEM;

    /* Send the ATCA Get Address Info command to get the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = 0x2c; 	/* Non-IPMI group netfn */
    msg.cmd = 1;	/* ATCA Get Address Info */
    data[0] = 0;	/* PICMG Identifier */
    msg.data = data;
    msg.data_len = 1;
    
    rspi->data1 = handler;
    rspi->data2 = cb_data;
    rv = conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			    atca_ipmb_handler, rspi);
    if (rv)
	ipmi_free_msg_item(rspi);

    /* Do an IP address check as part of the audit. */
    info->ipmb_call_count++;
    if (info->supports_ip_addr_checking
	|| ((info->ipmb_call_count % 128) == 0))
    {
	start_ip_addr_check(conn);
    }

    return rv;
}

static void
cleanup_atca_oem_data(ipmi_con_t *ipmi)
{
    atca_conn_info_t *info;

    if (ipmi->oem_data) {
	info = ipmi->oem_data;
	ipmi->oem_data = NULL;

	if (info->lock)
	    ipmi_destroy_lock(info->lock);

	if (info->fd_list) {
	    atca_conn_info_t *prev, *curr;
	    curr = *(info->fd_list);
	    prev = NULL;
	    while (curr) {
		if (curr == info) {
		    if (prev)
			prev->fd_next = curr->fd_next;
		    else
			*(info->fd_list) = curr->fd_next;
		    break;
		}
		curr = curr->fd_next;
	    }
	}

	if (info->ip_addrs)
	    ipmi_mem_free(info->ip_addrs);
	ipmi_mem_free(info);
    }
}

static int
atca_oem_finish_check(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t               *msg = &rspi->msg;
    ipmi_conn_oem_check_done done = rspi->data1;
    void                     *cb_data = rspi->data2;
    atca_conn_info_t         *info;
    int                      rv;

    if (!ipmi || ipmi->oem_data || (msg->data_len < 8) || (msg->data[0] != 0))
	goto out;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	ipmi_log(IPMI_LOG_SEVERE, "oem_atca_conn.c(atca_oem_finish_check):"
		 "Unable to allocate OEM connection info");
	goto out;
    }
    memset(info, 0, sizeof(*info));

    ipmi->oem_data = info;
    ipmi->oem_data_cleanup = cleanup_atca_oem_data;

    /* We've got an ATCA system, set up the handler. */
    ipmi->get_ipmb_addr = lan_atca_ipmb_fetch;
    /* Broadcast may or may not be broken on ATCA, but no I2C devices
       are allowed on the ATCA IPMB bus thus broadcast is not needed,
       and broadcast seems to be broken about half the time anyway,
       so... */
    ipmi->broadcast_broken = 1;

    /* Now try fetching the shelf manager IP addresses, but only
       on LAN connections. */
    if (strcmp(ipmi->con_type, "rmcp") == 0) {
	if (ipmi->get_num_ports && (ipmi->get_num_ports(ipmi) != 1)) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "oem_atca_conn.c(atca_oem_finish_check):"
		     " ATCA connection done with more than one IP port;"
		     " this is not allowed.  Disabling IP address"
		     " scanning.");
	    goto out;
	}

	rv = ipmi_create_lock_os_hnd(ipmi->os_hnd, &info->lock);
	if (rv) {
	    ipmi_log(IPMI_LOG_SEVERE,
		     "oem_atca_conn.c(atca_oem_finish_check):"
		     " Unable to allocate connection lock: 0x%x", rv);
	    goto out;
	}

	start_ip_addr_check(ipmi);
    }

 out:
    done(ipmi, cb_data);
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
atca_oem_check(ipmi_con_t               *conn,
	       void                     *check_cb_data,
	       ipmi_conn_oem_check_done done,
	       void                     *done_cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char 		 data[2];
    int                          rv;
    ipmi_msgi_t                  *rspi;

    rspi = ipmi_alloc_msg_item();
    if (!rspi)
	return ENOMEM;

    /* Send the ATCA Get Address Info command to get the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = IPMI_GROUP_EXTENSION_NETFN;
    msg.cmd = IPMI_PICMG_CMD_GET_ADDRESS_INFO;
    data[0] = IPMI_PICMG_GRP_EXT;
    msg.data = data;
    msg.data_len = 1;

    rspi->data1 = done;
    rspi->data2 = done_cb_data;
    rv = conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			    atca_oem_finish_check, rspi);
    if (rv)
	ipmi_free_msg_item(rspi);
    return rv;
}

static int
handle_intel_atca(ipmi_con_t *conn, void *cb_data)
{
    atca_conn_info_t *info = conn->oem_data;

    if (!info)
	return 0;

    /* This means that we don't advertise 0x20 as our address on the
       CMM, we use the real address. */
#if 0
    info->dont_use_floating_addr = 1;
#endif
    info->hacks = IPMI_CONN_HACK_20_AS_MAIN_ADDR;
    return 0;
}

static int atca_conn_initialized;

int
ipmi_oem_atca_conn_init(void)
{
    int rv;

    if (atca_conn_initialized)
	return 0;

    rv = ipmi_create_global_lock(&fd_lock);
    if (rv)
	return rv;

    rv = ipmi_register_conn_oem_check(atca_oem_check, NULL);
    if (rv) {
	ipmi_destroy_lock(fd_lock);
	return rv;
    }

    rv = ipmi_register_oem_conn_handler(0x000157, 0x0841,
					handle_intel_atca, NULL);
    if (rv) {
	ipmi_deregister_conn_oem_check(atca_oem_check, NULL);
	ipmi_destroy_lock(fd_lock);
	return rv;
    }

    rv = ipmi_register_oem_conn_handler(0x000157, 0x080b,
					handle_intel_atca, NULL);
    if (rv) {
	ipmi_deregister_oem_conn_handler(0x000157, 0x080b);
	ipmi_deregister_conn_oem_check(atca_oem_check, NULL);
	ipmi_destroy_lock(fd_lock);
	return rv;
    }

    rv = ipmi_register_oem_conn_handler(0x000157, 0x080c,
					handle_intel_atca, NULL);
    if (rv) {
	ipmi_deregister_oem_conn_handler(0x000157, 0x0841);
	ipmi_deregister_oem_conn_handler(0x000157, 0x080b);
	ipmi_deregister_conn_oem_check(atca_oem_check, NULL);
	ipmi_destroy_lock(fd_lock);
	return rv;
    }

    atca_conn_initialized = 1;

    return 0;
}

void
ipmi_oem_atca_conn_shutdown(void)
{
    if (fd_sock != -1) {
	os_handler_t *os_hnd = ipmi_get_global_os_handler();
	os_hnd->remove_fd_to_wait_for(os_hnd, fd_wait);
	close(fd_sock);
	fd_sock = -1;
    }

    if (atca_conn_initialized) {
	ipmi_destroy_lock(fd_lock);
	fd_lock = NULL;
	ipmi_deregister_conn_oem_check(atca_oem_check, NULL);
	ipmi_deregister_oem_conn_handler(0x000157, 0x0841);
	ipmi_deregister_oem_conn_handler(0x000157, 0x080c);
	ipmi_deregister_oem_conn_handler(0x000157, 0x080b);
	atca_conn_initialized = 0;
    }
}
