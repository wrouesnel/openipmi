/*
 * rakp.c
 *
 * MontaVista RMCP+ code for handling RAKP algorithms
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

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_lan.h>

#include <OpenIPMI/internal/ipmi_int.h>

typedef struct rakp_info_s
{
    ipmi_rmcpp_auth_info_t ainfo;

    ipmi_rmcpp_set_info_cb    set;
    ipmi_rmcpp_finish_auth_cb done;
    void                      *cb_data;
} rakp_info_t;

static int
check_rakp_rsp(ipmi_con_t   *ipmi,
	       rakp_info_t  *info,
	       ipmi_msg_t   *msg,
	       char         *caller,
	       unsigned int min_length,
	       int          addr_num)
{
    if (!ipmi) {
	info->done(ipmi, ECANCELED, addr_num, info->cb_data);
	return ECANCELED;
    }

    if (msg->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "rakp.c(%s): Message data too short: %d",
		 caller, msg->data_len);
	info->done(ipmi, EINVAL, addr_num, info->cb_data);
	return EINVAL;
    }

    if (msg->data[1]) {
	/* Got an RMCP+ error. */
	info->done(ipmi, IPMI_RMCPP_ERR_VAL(msg->data[1]), addr_num,
		   info->cb_data);
	return EINVAL;
    }

    if (msg->data_len < min_length) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "rakp.c(%s): Message data too short: %d",
		 caller, msg->data_len);
	info->done(ipmi, EINVAL, addr_num, info->cb_data);
	return EINVAL;
    }

    return 0;
}

static int
handle_rakp4(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t  *msg = &rspi->msg;
    rakp_info_t *info = rspi->data1;
    int         addr_num = (long) rspi->data4;
    int         rv;
    uint32_t    session_id;

    rv = check_rakp_rsp(ipmi, info, msg, "handle_rakp2", 40, addr_num);
    if (rv)
	goto out;

    session_id = ipmi_get_uint32(msg->data+4);
    if (session_id != info->ainfo.session_id) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "rakp.c(handle_rakp4): "
		 " Got wrong session id: 0x%x",
		 session_id);
	/* There's not way to report the error to the managed system,
	   just report it locally. */
	info->done(ipmi, EINVAL, addr_num, info->cb_data);
	goto out;
    }

    info->done(ipmi, 0, addr_num, info->cb_data);
    return IPMI_MSG_ITEM_NOT_USED;

 out:
    ipmi_mem_free(info);
    return IPMI_MSG_ITEM_NOT_USED;
}

static void
send_rakp3_err(ipmi_con_t *ipmi, rakp_info_t *info,
	       ipmi_msgi_t *rspi, int addr_num, int err)
{
    unsigned char               data[2];
    ipmi_msg_t                  msg;
    ipmi_rmcpp_nosession_addr_t addr;

    data[0] = 0;
    data[1] = err;

    msg.netfn = IPMI_RMCPP_DUMMY_NETFN;
    msg.cmd = IPMI_RMCPP_PAYLOAD_TYPE_RAKP_3;
    msg.data = data;
    msg.data_len = 2;
    addr.addr_type = IPMI_RMCPP_NOSESSION_ADDR_TYPE;
    rspi->data1 = info;

    ipmi_lan_send_command_forceip(ipmi, addr_num,
				  (ipmi_addr_t *) &addr, sizeof(addr),
				  &msg, NULL, rspi);
}

static int
send_rakp3(ipmi_con_t *ipmi, rakp_info_t *info,
	   ipmi_msgi_t *rspi, int addr_num)
{
    int                         rv;
    unsigned char               data[44];
    ipmi_msg_t                  msg;
    ipmi_rmcpp_nosession_addr_t addr;

    memset(data, 0, sizeof(data));
    data[0] = 0;
    ipmi_set_uint32(data+4, info->ainfo.mgsys_session_id);
    memcpy(data+8, info->ainfo.my_rand_num, 16);
    data[24] = info->ainfo.role;
    data[27] = info->ainfo.username_len;
    memcpy(data+28, info->ainfo.username, info->ainfo.username_len);

    msg.netfn = IPMI_RMCPP_DUMMY_NETFN;
    msg.cmd = IPMI_RMCPP_PAYLOAD_TYPE_RAKP_3;
    msg.data = data;
    msg.data_len = 28 + info->ainfo.username_len;
    addr.addr_type = IPMI_RMCPP_NOSESSION_ADDR_TYPE;
    rspi->data1 = info;

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, handle_rakp4, rspi);
    return rv;
}

static int
handle_rakp2(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t  *msg = &rspi->msg;
    rakp_info_t *info = rspi->data1;
    int         addr_num = (long) rspi->data4;
    int         rv;
    uint32_t    session_id;
    int         err = 0;

    rv = check_rakp_rsp(ipmi, info, msg, "handle_rakp2", 40, addr_num);
    if (rv) {
	err = IPMI_RMCPP_ILLEGAL_PARAMTER;
	goto out;
    }

    session_id = ipmi_get_uint32(msg->data+4);
    if (session_id != info->ainfo.session_id) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "rakp.c(handle_rakp2): "
		 " Got wrong session id: 0x%x",
		 session_id);
	info->done(ipmi, EINVAL, addr_num, info->cb_data);
	err = IPMI_RMCPP_INVALID_SESSION_ID;
	goto out;
    }

    memcpy(info->ainfo.mgsys_rand_num, msg->data+8, 16);
    memcpy(info->ainfo.mgsys_guid, msg->data+24, 16);

    rv = info->set(ipmi, addr_num, &info->ainfo, info->cb_data);
    if (rv) {
	info->done(ipmi, rv, addr_num, info->cb_data);
	err = IPMI_RMCPP_INSUFFICENT_RESOURCES_FOR_SESSION;
	goto out;
    }

    rv = send_rakp3(ipmi, info, rspi, addr_num);
    if (rv) {
	info->done(ipmi, rv, addr_num, info->cb_data);
	err = IPMI_RMCPP_INSUFFICENT_RESOURCES_FOR_SESSION;
	goto out;
    }

    return IPMI_MSG_ITEM_USED;

 out:
    send_rakp3_err(ipmi, info, rspi, addr_num, err);
    ipmi_mem_free(info);
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
send_rakp1(ipmi_con_t *ipmi, rakp_info_t *info,
	   ipmi_msgi_t *rspi, int addr_num)
{
    int                         rv;
    unsigned char               data[44];
    ipmi_msg_t                  msg;
    ipmi_rmcpp_nosession_addr_t addr;

    memset(data, 0, sizeof(data));
    data[0] = 0;
    ipmi_set_uint32(data+4, info->ainfo.mgsys_session_id);
    memcpy(data+8, info->ainfo.my_rand_num, 16);
    data[24] = info->ainfo.role;
    data[27] = info->ainfo.username_len;
    memcpy(data+28, info->ainfo.username, info->ainfo.username_len);

    msg.netfn = IPMI_RMCPP_DUMMY_NETFN;
    msg.cmd = IPMI_RMCPP_PAYLOAD_TYPE_RAKP_1;
    msg.data = data;
    msg.data_len = 28 + info->ainfo.username_len;
    addr.addr_type = IPMI_RMCPP_NOSESSION_ADDR_TYPE;
    rspi->data1 = info;

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, handle_rakp2, rspi);
    return rv;
}

static int
start_rakp(ipmi_con_t                *ipmi,
	   int                       addr_num,
	   ipmi_rmcpp_auth_info_t    *ainfo,
	   ipmi_rmcpp_set_info_cb    set,
	   ipmi_rmcpp_finish_auth_cb done,
	   void                      *cb_data)
{
    rakp_info_t *info;
    ipmi_msgi_t *rspi;
    int         rv;

    if ((ainfo->username_len > 16)
	|| (ainfo->password_len > 20))
    {
	return EINVAL;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    rspi = ipmi_alloc_msg_item();
    if (!rspi) {
	ipmi_mem_free(info);
	return ENOMEM;
    }

    info->ainfo = *ainfo;
    info->set = set;
    info->done = done;
    info->cb_data = cb_data;

    rv = ipmi->os_hnd->get_random(ipmi->os_hnd, info->ainfo.my_rand_num, 16);
    if (rv) {
	ipmi_free_msg_item(rspi);
	ipmi_mem_free(info);
	return rv;
    }

    rv = send_rakp1(ipmi, info, rspi, addr_num);
    if (rv) {
	ipmi_free_msg_item(rspi);
	ipmi_mem_free(info);
	return rv;
    }

    return 0;
}

static ipmi_rmcpp_authentication_t rakp_none_auth =
{
    start_rakp
};

/**********************************************************************
 *
 * RAKP message formatting
 *
 *********************************************************************/

static int
rakp_format_msg(ipmi_con_t    *ipmi,
		ipmi_addr_t   *addr,
		unsigned int  addr_len,
		ipmi_msg_t    *msg,
		unsigned char *out_data,
		unsigned int  *out_data_len,
		unsigned char seq)
{
    if (msg->data_len > *out_data_len)
	return E2BIG;

    memcpy(out_data, msg->data, msg->data_len);
    out_data[0] = seq;
    *out_data_len = msg->data_len;
    return 0;
}

static int
rakp_get_recv_seq(ipmi_con_t    *ipmi,
		  unsigned char *data,
		  unsigned int  data_len,
		  unsigned char *seq)
{
    if (data_len < 1)
	return EINVAL;

    *seq = data[0];
    return 0;
}

static int
rakp_handle_recv(ipmi_con_t    *ipmi,
		 ipmi_msgi_t   *rspi,
		 ipmi_addr_t   *orig_addr,
		 unsigned int  orig_addr_len,
		 ipmi_msg_t    *orig_msg,
		 unsigned char *data,
		 unsigned int  data_len)
{
    if (data_len > sizeof(rspi->data))
	return E2BIG;
    memcpy(rspi->data, data, data_len);
    return 0;
}

static void
rakp_handle_recv_async(ipmi_con_t    *ipmi,
		       unsigned char *tmsg,
		       unsigned int  data_len)
{
}

static ipmi_payload_t rakp_payload =
{ rakp_format_msg, rakp_get_recv_seq, rakp_handle_recv,
  rakp_handle_recv_async };

int
_ipmi_rakp_init(void)
{
    int rv;

    rv = ipmi_rmcpp_register_authentication
	(IPMI_LANP_AUTHENTICATION_ALGORITHM_RACKP_NONE,
	 &rakp_none_auth);
    if (rv)
	return rv;

    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_1,
				     &rakp_payload);
    if (rv)
	return rv;
    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_2,
				     &rakp_payload);
    if (rv)
	return rv;
    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_3,
				     &rakp_payload);
    if (rv)
	return rv;
    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_4,
				     &rakp_payload);
    if (rv)
	return rv;

    return 0;
}
