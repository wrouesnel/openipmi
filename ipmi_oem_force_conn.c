/*
 * ipmi_oem_force.c
 *
 * MontaVista IPMI code for handling Force Computer's boards.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_oem.h>
#include <OpenIPMI/ipmi_err.h>

void ipmb_handler(ipmi_con_t   *ipmi,
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
    
    if (msg->data[0] != 0)
	err = IPMI_IPMI_ERR_VAL(msg->data[0]);
    else if (msg->data_len < 4)
	err = EINVAL;
    else
	ipmb = msg->data[2];

    if (handler)
	handler(ipmi, err, ipmb, ipmb == 0x20, cb_data);
}

static int
force_ipmb_fetch(ipmi_con_t *conn, ipmi_ll_ipmb_addr_cb handler, void *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;

    /* Send the OEM command to get the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = 0x30;
    msg.cmd = 4;
    msg.data = NULL;
    msg.data_len = 0;

    return conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			      ipmb_handler, handler, cb_data, NULL, NULL);
}

void activate_handler(ipmi_con_t   *ipmi,
		      ipmi_addr_t  *addr,
		      unsigned int addr_len,
		      ipmi_msg_t   *rmsg,
		      void         *rsp_data1,
		      void         *rsp_data2,
		      void         *rsp_data3,
		      void         *rsp_data4)
{
    ipmi_ll_ipmb_addr_cb         handler = rsp_data1;
    void                         *cb_data = rsp_data2;
    unsigned char                ipmb = 0;
    int                          err = 0;
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    int                          rv;
    
    if (rmsg->data[0] != 0) {
	err = IPMI_IPMI_ERR_VAL(rmsg->data[0]);
	if (handler)
	    handler(ipmi, err, ipmb, 0, cb_data);
    }
    else {
	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = 0xf;
	si.lun = 0;
	msg.netfn = 0x30;
	msg.cmd = 4;
	msg.data = NULL;
	msg.data_len = 0;

	/* Now fetch the current state. */
	rv = ipmi->send_command(ipmi, (ipmi_addr_t *) &si, sizeof(si), &msg,
				ipmb_handler, handler, cb_data, NULL, NULL);
	if (rv) {
	    if (handler)
		handler(ipmi, err, ipmb, 0, cb_data);
	}
    }
}

static int
force_activate(ipmi_con_t           *conn,
	       int                  active,
	       ipmi_ll_ipmb_addr_cb handler,
	       void                 *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char                data[1];

    /* Send the OEM command to get the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = 0x30;
    msg.cmd = 3;
    if (active)
	data[0] = 0;
    else
	data[0] = 1;
    msg.data = data;
    msg.data_len = 1;

    return conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			      activate_handler, handler, cb_data, NULL, NULL);
}

static int
force_oem_conn_handler(ipmi_con_t *conn, void *cb_data)
{
    conn->get_ipmb_addr = force_ipmb_fetch;
    conn->set_active_state = force_activate;
    return 0;
}

void
init_oem_force_conn(void)
{
    int rv;

    /* The 735 card */
    rv = ipmi_register_oem_conn_handler(0x000e48,
					0x0804,
					force_oem_conn_handler,
					NULL);
    if (rv)
	fprintf(stderr, "Unable to initialize the Force 735 OEM handler\n");

    /* The 740 card */
    rv = ipmi_register_oem_conn_handler(0x000e48,
					0x0808,
					force_oem_conn_handler,
					NULL);
    if (rv)
	fprintf(stderr, "Unable to initialize the Force 740 OEM handler\n");

    /* The 786 card */
    rv = ipmi_register_oem_conn_handler(0x000e48,
					0x0810,
					force_oem_conn_handler,
					NULL);
    if (rv)
	fprintf(stderr, "Unable to initialize the Force 786 OEM handler\n");

    /* The 550 card */
    rv = ipmi_register_oem_conn_handler(0x000e48,
					0x0880,
					force_oem_conn_handler,
					NULL);
    if (rv)
	fprintf(stderr, "Unable to initialize the Force 550 OEM handler\n");

    /* The 560 card */
    rv = ipmi_register_oem_conn_handler(0x000e48,
					0x0888,
					force_oem_conn_handler,
					NULL);
    if (rv)
	fprintf(stderr, "Unable to initialize the Force 560 OEM handler\n");

    /* The 690 card */
    rv = ipmi_register_oem_conn_handler(0x000e48,
					0x0900,
					force_oem_conn_handler,
					NULL);
    if (rv)
	fprintf(stderr, "Unable to initialize the Force 690 OEM handler\n");

    /* The 695 card */
    rv = ipmi_register_oem_conn_handler(0x000e48,
					0x0904,
					force_oem_conn_handler,
					NULL);
    if (rv)
	fprintf(stderr, "Unable to initialize the Force 695 OEM handler\n");
}

#if 0
/* If you include this as a module under Linux, you can use the
   following code to initialize it.  Otherwise, something has to call
   init_oem_force_conn(). */
static void (*const __init_patch_debug[1])                                    \
   (void) __attribute__ ((section(".ctors"))) = { init_oem_force };
#endif
