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

typedef struct rakp_info_s
{
    ipmi_rmcpp_auth_info_t ainfo;

    ipmi_rmcpp_set_info_cb    set;
    ipmi_rmcpp_finish_auth_cb done;
    void                      *cb_data;
} rakp_info_t;

static int
check_rakp_rsp(ipmi_con_t   *ipmi,
	       ipmi_msg_t   *msg,
	       char         *caller,
	       unsigned int min_length,
	       int          addr_num)
{
    if (!ipmi) {
	handle_connected(ipmi, ECANCELED, addr_num);
	return ECANCELED;
    }

    if (msg->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan.c(%s): Message data too short: %d",
		 caller, msg->data_len);
	handle_connected(ipmi, EINVAL, addr_num);
	return EINVAL;
    }

    if (msg->data[1]) {
	/* Got an RMCP+ error. */
	handle_connected(ipmi, IPMI_RMCPP_ERR_VAL(msg->data[1]), addr_num);
	return EINVAL;
    }

    if (msg->data_len < min_length) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "ipmi_lan.c(%s): Message data too short: %d",
		 caller, msg->data_len);
	handle_connected(ipmi, EINVAL, addr_num);
	return EINVAL;
    }

    return 0;
}

static int
send_rakp1(ipmi_con_t *ipmi, rakp_data_t *info,
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
    data[24] = 
    

    data[8] = 0; /* auth algorithm */
    if (lan->requested_auth == IPMI_LANP_AUTHENTICATION_ALGORITHM_BMCPICK)
	data[11] = 0; /* Let the BMC pick */
    else {
	data[11] = 8;
	data[12] = lan->requested_auth;
    }
    data[16] = 1; /* integrity algorithm */
    if (lan->requested_integ == IPMI_LANP_INTEGRITY_ALGORITHM_BMCPICK)
	data[19] = 0; /* Let the BMC pick */
    else {
	data[19] = 8;
	data[20] = lan->requested_integ;
    }
    data[24] = 2; /* confidentiality algorithm */
    if (lan->requested_conf == IPMI_LANP_CONFIDENTIALITY_ALGORITHM_BMCPICK)
	data[27] = 0; /* Let the BMC pick */
    else {
	data[27] = 8;
	data[28] = lan->requested_integ;
    }

    msg.netfn = IPMI_RMCPP_DUMMY_NETFN;
    msg.cmd = IPMI_RMCPP_PAYLOAD_TYPE_OPEN_SESSION_REQUEST;
    msg.data = data;
    msg.data_len = 32;
    addr.addr_type = IPMI_RMCPP_NOSESSION_ADDR_TYPE;

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, got_rmcpp_open_session_rsp, rspi);
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

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;

    info->ainfo = *ainfo;
    info->set = set;
    info->done = done;
    info->cb_data = cb_data;

    if ((ainfo->username_len > 16)
	|| (ainfo->password_len > 20))
    {
	return EINVAL;
    }

    rv = ipmi->os_hnd->get_random(ipmi->os_hnd, info->ainfo.my_rand_num, 16);
    if (rv) {
	ipmi_mem_free(info);
	return rv;
    }

    
}


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
    return ENOSYS;
}

static ipmi_payload_t rakp_payload =
{ rakp_format_msg, rakp_get_recv_seq, rakp_handle_recv,
  rakp_handle_recv_async };

int
_ipmi_rakp_init(void)
{
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
