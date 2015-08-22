/*
 * rakp.c
 *
 * MontaVista RMCP+ code for handling RAKP algorithms
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

#include <config.h>

#include <string.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_lan.h>

#include <OpenIPMI/internal/ipmi_int.h>

typedef struct rakp_info_s rakp_info_t;

typedef int (*init_cb)(rakp_info_t *info);
typedef void (*cleanup_cb)(rakp_info_t *info);
typedef int (*check_cb)(rakp_info_t   *info,
			unsigned char *data,
			unsigned int  data_len);
typedef int (*set_cb)(rakp_info_t   *info,
		      unsigned char *data,
		      unsigned int  *data_len,
		      unsigned int  total_len);

struct rakp_info_s
{
    ipmi_rmcpp_auth_t *ainfo;

    ipmi_rmcpp_set_info_cb    set;
    ipmi_rmcpp_finish_auth_cb done;
    void                      *cb_data;

    unsigned int  hacks;

    unsigned char msg_tag;

    void *key_data;

    /* Check an set the auth keys for the various rakp messages.  The
       data passed in is the whole message.  For set3, the data_len
       points to the current message size and total_len is the
       total_len available.  It should update data_len to the actual
       length.  These functions may be NULL and will not be used. */
    cleanup_cb cleanup;
    check_cb   check2;
    set_cb     set3;
    check_cb   check4;
};

static void
rakp_done(rakp_info_t *info,
	  ipmi_con_t  *ipmi,
	  int         addr_num,
	  int         err)
{
    info->done(ipmi, err, addr_num, info->cb_data);
    if (info->cleanup)
	info->cleanup(info);
    ipmi_mem_free(info);
}

static int
check_rakp_rsp(ipmi_con_t   *ipmi,
	       rakp_info_t  *info,
	       ipmi_msg_t   *msg,
	       char         *caller,
	       unsigned int min_length,
	       int          addr_num)
{
    if (!ipmi)
	return ECANCELED;

    if (msg->data_len == 1) {
	/* This is kind of a cheap hack, this can happen when there is
	   a timeout. */
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "rakp.c(%s): IPMI error: %d",
		 caller, msg->data[0]);
	return IPMI_IPMI_ERR_VAL(msg->data[0]);
    }

    if (msg->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "rakp.c(%s): Message data too short: %d",
		 caller, msg->data_len);
	return EINVAL;
    }

    if (msg->data[1])
	/* Got an RMCP+ error. */
	return IPMI_RMCPP_ERR_VAL(msg->data[1]);

    if (msg->data_len < min_length) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "rakp.c(%s): Message data too short: %d",
		 caller, msg->data_len);
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

    /* In this function, there's not way to report the error to the
       managed system, just report it locally. */

    rv = check_rakp_rsp(ipmi, info, msg, "handle_rakp4", 8, addr_num);
    if (rv)
	goto out;

    if (info->check4) {
	rv = info->check4(info, msg->data, msg->data_len);
	if (rv)
	    goto out;
    }

    session_id = ipmi_get_uint32(msg->data+4);
    if (session_id != ipmi_rmcpp_auth_get_my_session_id(info->ainfo)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "rakp.c(handle_rakp4): "
		 " Got wrong session id: 0x%x",
		 session_id);
	rv = EINVAL;
	goto out;
    }

    rakp_done(info, ipmi, addr_num, 0);
    return IPMI_MSG_ITEM_NOT_USED;

 out:
    rakp_done(info, ipmi, addr_num, rv);
    return IPMI_MSG_ITEM_NOT_USED;
}

static int
send_rakp3(ipmi_con_t *ipmi, rakp_info_t *info,
	   ipmi_msgi_t *rspi, int addr_num, int err)
{
    int                 rv;
    unsigned char       data[64];
    ipmi_msg_t          msg;
    ipmi_rmcpp_addr_t   addr;

    memset(data, 0, sizeof(data));
    data[0] = info->msg_tag;
    data[1] = err;
    ipmi_set_uint32(data+4, ipmi_rmcpp_auth_get_mgsys_session_id(info->ainfo));

    msg.netfn = IPMI_RMCPP_DUMMY_NETFN;
    msg.cmd = 0;
    msg.data = data;
    msg.data_len = 8;
    addr.addr_type = IPMI_RMCPP_ADDR_START + IPMI_RMCPP_PAYLOAD_TYPE_RAKP_3;
    rspi->data1 = info;

    if (info->set3) {
	unsigned int len;
	len = msg.data_len;
	rv = info->set3(info, data, &len, sizeof(data));
	if (rv)
	    return rv;
	msg.data_len = len;
    }

    if (err)
	/* Don't handle the responst (if one comes back) on an error. */
	rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
					   (ipmi_addr_t *) &addr, sizeof(addr),
					   &msg, NULL, rspi);
    else
	rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
					   (ipmi_addr_t *) &addr, sizeof(addr),
					   &msg, handle_rakp4, rspi);
    return rv;
}

static int
handle_rakp2(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t    *msg = &rspi->msg;
    rakp_info_t   *info = rspi->data1;
    int           addr_num = (long) rspi->data4;
    int           rv;
    uint32_t      session_id;
    int           err = 0;
    unsigned char *p;
    unsigned int  plen;
    int           rv2;

    rv = check_rakp_rsp(ipmi, info, msg, "handle_rakp2", 40, addr_num);
    if (rv) {
	err = IPMI_RMCPP_ILLEGAL_PARAMETER;
	goto out;
    }

    p = ipmi_rmcpp_auth_get_mgsys_rand(info->ainfo, &plen);
    if (plen < 16)
	return EINVAL;
    memcpy(p, msg->data+8, 16);
    ipmi_rmcpp_auth_set_mgsys_rand_len(info->ainfo, 16);

    p = ipmi_rmcpp_auth_get_mgsys_guid(info->ainfo, &plen);
    if (plen < 16)
	return EINVAL;
    memcpy(p, msg->data+24, 16);
    ipmi_rmcpp_auth_set_mgsys_guid_len(info->ainfo, 16);

    session_id = ipmi_get_uint32(msg->data+4);
    if (session_id != ipmi_rmcpp_auth_get_my_session_id(info->ainfo)) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "rakp.c(handle_rakp2): "
		 " Got wrong session id: 0x%x",
		 session_id);
	err = IPMI_RMCPP_INVALID_SESSION_ID;
	goto out;
    }

    if (info->check2) {
	rv = info->check2(info, msg->data, msg->data_len);
	if (rv) {
	    if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
		ipmi_log(IPMI_LOG_DEBUG, "Integrity check fail for rakp 2");
	    err = IPMI_RMCPP_INVALID_INTEGRITY_CHECK_VALUE;
	    goto out;
	}
    }

    rv = info->set(ipmi, addr_num, info->ainfo, info->cb_data);
    if (rv) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Error setting values from rakp 2");
	err = IPMI_RMCPP_INSUFFICIENT_RESOURCES_FOR_SESSION;
	goto out;
    }

    rv = send_rakp3(ipmi, info, rspi, addr_num, 0);
    if (rv) {
	if (DEBUG_RAWMSG || DEBUG_MSG_ERR)
	    ipmi_log(IPMI_LOG_DEBUG, "Error sending rakp 3");
	err = IPMI_RMCPP_INSUFFICIENT_RESOURCES_FOR_SESSION;
	goto out;
    }

    return IPMI_MSG_ITEM_USED;

 out:
    rv2 = EINVAL;
    if (ipmi)
	rv2 = send_rakp3(ipmi, info, rspi, addr_num, err);
    rakp_done(info, ipmi, addr_num, rv);
    if (rv2)
	return IPMI_MSG_ITEM_NOT_USED;
    else
	/* Yes, we use it to send the error response. */
	return IPMI_MSG_ITEM_USED;
}

static int
send_rakp1(ipmi_con_t *ipmi, rakp_info_t *info,
	   ipmi_msgi_t *rspi, int addr_num)
{
    int                 rv;
    unsigned char       data[44];
    ipmi_msg_t          msg;
    ipmi_rmcpp_addr_t   addr;
    const unsigned char *p;
    unsigned int        plen;

    memset(data, 0, sizeof(data));
    data[0] = info->msg_tag;
    ipmi_set_uint32(data+4, ipmi_rmcpp_auth_get_mgsys_session_id(info->ainfo));

    p = ipmi_rmcpp_auth_get_my_rand(info->ainfo, &plen);
    if (plen < 16)
	return EINVAL;
    memcpy(data+8, p, 16);

    data[24] = ipmi_rmcpp_auth_get_role(info->ainfo);
    data[27] = ipmi_rmcpp_auth_get_username_len(info->ainfo);
    p = ipmi_rmcpp_auth_get_username(info->ainfo, &plen);
    if (plen < 16)
	return EINVAL;
    memcpy(data+28, p, data[27]);

    msg.netfn = IPMI_RMCPP_DUMMY_NETFN;
    msg.cmd = 0;
    msg.data = data;
    msg.data_len = 28 + data[27];
    addr.addr_type = IPMI_RMCPP_ADDR_START + IPMI_RMCPP_PAYLOAD_TYPE_RAKP_1;
    rspi->data1 = info;

    rv = ipmi_lan_send_command_forceip(ipmi, addr_num,
				       (ipmi_addr_t *) &addr, sizeof(addr),
				       &msg, handle_rakp2, rspi);
    return rv;
}

static int
start_rakp(ipmi_con_t                *ipmi,
	   int                       addr_num,
	   unsigned char             msg_tag,
	   ipmi_rmcpp_auth_t         *ainfo,
	   init_cb                   init,
	   cleanup_cb                cleanup,
	   check_cb                  check2,
	   set_cb                    set3,
	   check_cb                  check4,
	   ipmi_rmcpp_set_info_cb    set,
	   ipmi_rmcpp_finish_auth_cb done,
	   void                      *cb_data)
{
    rakp_info_t   *info;
    ipmi_msgi_t   *rspi;
    int           rv;
    unsigned char *p;
    unsigned int  plen;

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info)
	return ENOMEM;
    memset(info, 0, sizeof(*info));

    rspi = ipmi_alloc_msg_item();
    if (!rspi) {
	ipmi_mem_free(info);
	return ENOMEM;
    }

    info->msg_tag = msg_tag;
    info->ainfo = ainfo;
    info->cleanup = cleanup;
    info->set = set;
    info->done = done;
    info->cb_data = cb_data;
    info->check2 = check2;
    info->set3 = set3;
    info->check4 = check4;
    info->hacks = ipmi->hacks;

    p = ipmi_rmcpp_auth_get_my_rand(info->ainfo, &plen);
    if (plen < 16)
	return EINVAL;
    ipmi_rmcpp_auth_set_my_rand_len(info->ainfo, 16);
    rv = ipmi->os_hnd->get_random(ipmi->os_hnd, p, 16);
    if (rv) {
	ipmi_free_msg_item(rspi);
	ipmi_mem_free(info);
	return rv;
    }

    if (init) {
	rv = init(info);
	if (rv) {
	    ipmi_free_msg_item(rspi);
	    ipmi_mem_free(info);
	    return rv;
	}
    }

    rv = send_rakp1(ipmi, info, rspi, addr_num);
    if (rv) {
	if (cleanup)
	    cleanup(info);
	ipmi_free_msg_item(rspi);
	ipmi_mem_free(info);
	return rv;
    }

    return 0;
}


static int
start_rakp_none(ipmi_con_t                *ipmi,
		int                       addr_num,
		unsigned char             msg_tag,
		ipmi_rmcpp_auth_t         *ainfo,
		ipmi_rmcpp_set_info_cb    set,
		ipmi_rmcpp_finish_auth_cb done,
		void                      *cb_data)
{
    return start_rakp(ipmi, addr_num, msg_tag, ainfo,
		      NULL, NULL, NULL, NULL, NULL,
		      set, done, cb_data);
}

static ipmi_rmcpp_authentication_t rakp_none_auth =
{
    start_rakp_none
};

/***********************************************************************
 *
 * cipher handling
 *
 ***********************************************************************/
#ifdef HAVE_OPENSSL
#include <openssl/hmac.h>

typedef struct rakp_hmac_key_s
{
    unsigned int key_len;
    unsigned int integ_len;
    const EVP_MD *evp_md;
} rakp_hmac_key_t;

static int
rakp_hmac_c2(rakp_info_t   *info,
	     unsigned char *data,
	     unsigned int  data_len)
{
    unsigned char       idata[74];
    unsigned int        ilen;
    unsigned char       integ_data[20];
    rakp_hmac_key_t     *rinfo = info->key_data;
    const unsigned char *p;
    unsigned char       *s;
    unsigned char       *k;
    unsigned int        plen;

    if (data_len < 40+rinfo->key_len)
	return E2BIG;

    ipmi_set_uint32(idata+0, ipmi_rmcpp_auth_get_my_session_id(info->ainfo));
    ipmi_set_uint32(idata+4, ipmi_rmcpp_auth_get_mgsys_session_id(info->ainfo));
    p = ipmi_rmcpp_auth_get_my_rand(info->ainfo, &plen);
    memcpy(idata+8, p, 16);
    p = ipmi_rmcpp_auth_get_mgsys_rand(info->ainfo, &plen);
    memcpy(idata+24, p, 16);
    p = ipmi_rmcpp_auth_get_mgsys_guid(info->ainfo, &plen);
    memcpy(idata+40, p, 16);
    idata[56] = ipmi_rmcpp_auth_get_role(info->ainfo);
    idata[57] = ipmi_rmcpp_auth_get_username_len(info->ainfo);
    if (idata[57] > 16)
	return EINVAL;
    p = ipmi_rmcpp_auth_get_username(info->ainfo, &plen);
    memcpy(idata+58, p, idata[57]);

    p = ipmi_rmcpp_auth_get_password(info->ainfo, &plen);
    if (plen < rinfo->key_len)
	return EINVAL;
    HMAC(rinfo->evp_md, p, rinfo->key_len, idata, 58+idata[57], integ_data, &ilen);
    if (memcmp(data+40, integ_data, rinfo->key_len) != 0)
	return EINVAL;

    /* Now generate the SIK */
    p = ipmi_rmcpp_auth_get_my_rand(info->ainfo, &plen);
    memcpy(idata+0, p, 16);
    p = ipmi_rmcpp_auth_get_mgsys_rand(info->ainfo, &plen);
    memcpy(idata+16, p, 16);
    idata[32] = ipmi_rmcpp_auth_get_role(info->ainfo);
    idata[33] = ipmi_rmcpp_auth_get_username_len(info->ainfo);
    p = ipmi_rmcpp_auth_get_username(info->ainfo, &plen);
    memcpy(idata+34, p, idata[33]);
    p = ipmi_rmcpp_auth_get_bmc_key(info->ainfo, &plen);
    if (plen < rinfo->key_len)
	return EINVAL;
    s = ipmi_rmcpp_auth_get_sik(info->ainfo, &plen);
    if (plen < rinfo->key_len)
	return EINVAL;
    HMAC(rinfo->evp_md, p, rinfo->key_len, idata, 34+idata[33], s, &ilen);
    ipmi_rmcpp_auth_set_sik_len(info->ainfo, rinfo->key_len);

    /* Now generate k1 and k2. */
    k = ipmi_rmcpp_auth_get_k1(info->ainfo, &plen);
    if (plen < rinfo->key_len)
	return EINVAL;
    memset(idata, 1, rinfo->key_len);
    HMAC(rinfo->evp_md, s, rinfo->key_len, idata, rinfo->key_len, k, &ilen);
    ipmi_rmcpp_auth_set_k2_len(info->ainfo, rinfo->key_len);
    k = ipmi_rmcpp_auth_get_k2(info->ainfo, &plen);
    if (plen < rinfo->key_len)
	return EINVAL;
    memset(idata, 2, rinfo->key_len);
    HMAC(rinfo->evp_md, s, rinfo->key_len, idata, rinfo->key_len, k, &ilen);
    ipmi_rmcpp_auth_set_k2_len(info->ainfo, rinfo->key_len);

    return 0;
}

static int
rakp_hmac_s3(rakp_info_t   *info,
	     unsigned char *data,
	     unsigned int  *data_len,
	     unsigned int  total_len)
{
    unsigned char       idata[38];
    unsigned int        ilen;
    rakp_hmac_key_t     *rinfo = info->key_data;
    const unsigned char *p;
    unsigned int        plen;

    if (((*data_len)+rinfo->key_len) > total_len)
	return E2BIG;

    p = ipmi_rmcpp_auth_get_mgsys_rand(info->ainfo, &plen);
    memcpy(idata+0, p, 16);
    ipmi_set_uint32(idata+16, ipmi_rmcpp_auth_get_my_session_id(info->ainfo));
    idata[20] = ipmi_rmcpp_auth_get_role(info->ainfo);
    if (info->hacks & IPMI_CONN_HACK_RAKP3_WRONG_ROLEM)
	/* For the RAKP3 message, the Intel BMC only uses the bottom 4
	   nibbles. */
	idata[20] &= 0xf;
    idata[21] = ipmi_rmcpp_auth_get_username_len(info->ainfo);
    if (idata[21] > 16)
	return EINVAL;
    p = ipmi_rmcpp_auth_get_username(info->ainfo, &plen);
    memcpy(idata+22, p, idata[21]);

    p = ipmi_rmcpp_auth_get_password(info->ainfo, &plen);
    if (plen < rinfo->key_len)
	return EINVAL;

    HMAC(rinfo->evp_md, p, rinfo->key_len, idata, 22+idata[21],
	 data+*data_len, &ilen);
    *data_len += rinfo->key_len;
    return 0;
}

static int
rakp_hmac_c4(rakp_info_t   *info,
	     unsigned char *data,
	     unsigned int  data_len)
{
    unsigned char       idata[36];
    unsigned int        ilen;
    unsigned char       integ_data[20];
    rakp_hmac_key_t     *rinfo = info->key_data;
    const unsigned char *p;
    unsigned int        plen;

    if (data_len < 8+rinfo->integ_len)
	return E2BIG;

    p = ipmi_rmcpp_auth_get_my_rand(info->ainfo, &plen);
    memcpy(idata+0, p, 16);
    ipmi_set_uint32(idata+16, ipmi_rmcpp_auth_get_mgsys_session_id(info->ainfo));
    p = ipmi_rmcpp_auth_get_mgsys_guid(info->ainfo, &plen);
    if (plen < 16)
	return EINVAL;
    memcpy(idata+20, p, 16);

    p = ipmi_rmcpp_auth_get_sik(info->ainfo, &plen);
    HMAC(rinfo->evp_md, p, rinfo->key_len, idata, 36, integ_data, &ilen);
    if (memcmp(data+8, integ_data, rinfo->integ_len) != 0)
	return EINVAL;

    return 0;
}

static void
rakp_hmac_cleanup(rakp_info_t *info)
{
    rakp_hmac_key_t *key_data = info->key_data;

    ipmi_mem_free(key_data);
}

static int
rakp_sha1_init(rakp_info_t *info)
{
    rakp_hmac_key_t *key_data;

    key_data = ipmi_mem_alloc(sizeof(*key_data));
    if (!key_data)
	return ENOMEM;
    key_data->evp_md = EVP_sha1();
    key_data->key_len = 20;
    key_data->integ_len = 12;
    info->key_data = key_data;
    return 0;
}

static int
start_rakp_hmac_sha1(ipmi_con_t                *ipmi,
		     int                       addr_num,
		     unsigned char             msg_tag,
		     ipmi_rmcpp_auth_t         *ainfo,
		     ipmi_rmcpp_set_info_cb    set,
		     ipmi_rmcpp_finish_auth_cb done,
		     void                      *cb_data)
{
    return start_rakp(ipmi, addr_num, msg_tag, ainfo,
		      rakp_sha1_init, rakp_hmac_cleanup,
		      rakp_hmac_c2, rakp_hmac_s3, rakp_hmac_c4,
		      set, done, cb_data);
}

static ipmi_rmcpp_authentication_t rakp_hmac_sha1_auth =
{
    start_rakp_hmac_sha1
};

static int
rakp_md5_init(rakp_info_t *info)
{
    rakp_hmac_key_t *key_data;

    key_data = ipmi_mem_alloc(sizeof(*key_data));
    if (!key_data)
	return ENOMEM;
    key_data->evp_md = EVP_md5();
    key_data->key_len = 16;
    key_data->integ_len = 16;
    info->key_data = key_data;
    return 0;
}

static int
start_rakp_hmac_md5(ipmi_con_t                *ipmi,
		    int                       addr_num,
		    unsigned char             msg_tag,
		    ipmi_rmcpp_auth_t         *ainfo,
		    ipmi_rmcpp_set_info_cb    set,
		    ipmi_rmcpp_finish_auth_cb done,
		    void                      *cb_data)
{
    return start_rakp(ipmi, addr_num, msg_tag, ainfo,
		      rakp_md5_init, rakp_hmac_cleanup,
		      rakp_hmac_c2, rakp_hmac_s3, rakp_hmac_c4,
		      set, done, cb_data);
}

static ipmi_rmcpp_authentication_t rakp_hmac_md5_auth =
{
    start_rakp_hmac_md5
};
#endif

/**********************************************************************
 *
 * RAKP message formatting
 *
 *********************************************************************/

static int
rakp_format_msg(ipmi_con_t        *ipmi,
		const ipmi_addr_t *addr,
		unsigned int      addr_len,
		const ipmi_msg_t  *msg,
		unsigned char     *out_data,
		unsigned int      *out_data_len,
		int	          *out_of_session,
		unsigned char     seq)
{
    if (msg->data_len > *out_data_len)
	return E2BIG;

    memcpy(out_data, msg->data, msg->data_len);
    out_data[0] = seq;
    *out_of_session = 1;
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
    ipmi_msg_t *msg = &(rspi->msg);
    if (data_len > sizeof(rspi->data))
	return E2BIG;
    memcpy(rspi->data, data, data_len);
    msg->data = rspi->data;
    msg->data_len = data_len;
    return 0;
}

static void
rakp_handle_recv_async(ipmi_con_t    *ipmi,
		       unsigned char *tmsg,
		       unsigned int  data_len)
{
}

static int
rakp_get_msg_tag(unsigned char *tmsg,
		 unsigned int  data_len,
		 unsigned char *tag)
{
    if (data_len < 8)
	return EINVAL;
    *tag = ipmi_get_uint32(tmsg+4) - 1; /* session id */
    return 0;
}

static ipmi_payload_t rakp_payload =
{ rakp_format_msg, rakp_get_recv_seq, rakp_handle_recv,
  rakp_handle_recv_async, rakp_get_msg_tag };

void
_ipmi_rakp_shutdown(void)
{
    ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_4, NULL);
    ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_3, NULL);
    ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_2, NULL);
    ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_1, NULL);
#ifdef HAVE_OPENSSL
    ipmi_rmcpp_register_authentication
	(IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_MD5, NULL);
    ipmi_rmcpp_register_authentication
	(IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_SHA1, NULL);
#endif
    ipmi_rmcpp_register_authentication
	(IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_NONE, NULL);
}

int
_ipmi_rakp_init(void)
{
    int rv;

    rv = ipmi_rmcpp_register_authentication
	(IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_NONE,
	 &rakp_none_auth);
    if (rv)
	return rv;

#ifdef HAVE_OPENSSL
    rv = ipmi_rmcpp_register_authentication
	(IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_SHA1,
	 &rakp_hmac_sha1_auth);
    if (rv) {
	_ipmi_rakp_shutdown();
	return rv;
    }

    rv = ipmi_rmcpp_register_authentication
	(IPMI_LANP_AUTHENTICATION_ALGORITHM_RAKP_HMAC_MD5,
	 &rakp_hmac_md5_auth);
    if (rv) {
	_ipmi_rakp_shutdown();
	return rv;
    }
#endif

    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_1,
				     &rakp_payload);
    if (rv) {
	_ipmi_rakp_shutdown();
	return rv;
    }

    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_2,
				     &rakp_payload);
    if (rv) {
	_ipmi_rakp_shutdown();
	return rv;
    }

    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_3,
				     &rakp_payload);
    if (rv) {
	_ipmi_rakp_shutdown();
	return rv;
    }

    rv = ipmi_rmcpp_register_payload(IPMI_RMCPP_PAYLOAD_TYPE_RAKP_4,
				     &rakp_payload);
    if (rv) {
	_ipmi_rakp_shutdown();
	return rv;
    }

    return 0;
}
