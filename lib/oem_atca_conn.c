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

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_err.h>

static void
atca_ipmb_handler(ipmi_con_t   *ipmi,
		  ipmi_addr_t  *addr,
		  unsigned int addr_len,
		  ipmi_msg_t   *msg,
		  void         *rsp_data1,
		  void         *rsp_data2,
		  void         *rsp_data3,
		  void         *rsp_data4)
{
    ipmi_ll_ipmb_addr_cb handler = rsp_data1;
    void                 *cb_data = rsp_data2;
    unsigned char        ipmb = 0;
    int                  err = 0;

    if (!ipmi) {
	err = ECANCELED;
	goto out_handler;
    }

    if (msg->data[0] != 0) 
	err = IPMI_IPMI_ERR_VAL(msg->data[0]);
    else if (msg->data_len < 4)
	err = EINVAL;
    else if (msg->data[7] == 3)
	ipmb = 0x20; /* This is a Dedicated ShMC*/
    else
	ipmb = msg->data[3];

    /* Note that there is no "inactive" connection with ATCA. */
    if (!err)
	ipmi->set_ipmb_addr(ipmi, ipmb, 1);

 out_handler:
    if (handler)
	handler(ipmi, err, ipmb, 1, cb_data);
}

static int
lan_atca_ipmb_fetch(ipmi_con_t           *conn,
		    ipmi_ll_ipmb_addr_cb handler,
		    void                 *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char 		 data[2];

    /* Send the ATCA Get Address Info command to get the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = 0x2c; 	/* Non-IPMI group netfn */
    msg.cmd = 1;	/* ATCA Get Address Info */
    data[0] = 0;	/* PICMG Identifier */
    msg.data = data;
    msg.data_len = 1;

    return conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			      atca_ipmb_handler,
			      handler, cb_data, NULL, NULL);
}

static void
atca_oem_finish_check(ipmi_con_t   *ipmi,
		      ipmi_addr_t  *addr,
		      unsigned int addr_len,
		      ipmi_msg_t   *msg,
		      void         *rsp_data1,
		      void         *rsp_data2,
		      void         *rsp_data3,
		      void         *rsp_data4)
{
    ipmi_conn_oem_check_done done = rsp_data1;
    void                     *cb_data = rsp_data2;

    if (ipmi && (msg->data_len >= 8) && (msg->data[0] == 0)) {
	/* We've got an ATCA system, set up the handler. */
	ipmi->get_ipmb_addr = lan_atca_ipmb_fetch;
	/* Broadcast may or may not be broken on ATCA, but no I2C devices
	   are allowed on the ATCA IPMB bus thus broadcast is not needed,
	   and broadcast seems to be broken about half the time anyway,
	   so... */
	ipmi->broadcast_broken = 1;
    }
    done(ipmi, cb_data);
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

    /* Send the ATCA Get Address Info command to get the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = 0x2c; 	/* Non-IPMI group netfn */
    msg.cmd = 1;	/* ATCA Get Address Info */
    data[0] = 0;	/* PICMG Identifier */
    msg.data = data;
    msg.data_len = 1;

    return conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			      atca_oem_finish_check,
			      done, done_cb_data, NULL, NULL);
}

int
ipmi_oem_atca_conn_init(void)
{
    return ipmi_register_conn_oem_check(atca_oem_check, NULL);
}

void
ipmi_oem_atca_conn_shutdown(void)
{
    ipmi_deregister_conn_oem_check(atca_oem_check, NULL);
}
