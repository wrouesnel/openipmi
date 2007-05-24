/* oem_kontron_conn.c - OpenIPMI oem handler for Kontron boards */

/* 
  Kontron IPMI code for handling Kontron CPCI and AMC boards.

  This file reuse parts of the code from ipmi_oem_force.c source 
  from OpenIPMI library. 

  Modified by: T.Smolinski, M.Ptak, Gerhard Obrecht
  Kontron Modular Computers

  v02 2006 Jun 22: translateAdrs_amc enhanced for uATCA (12 modules max.)
                   Added AM4002, AM4010, CP6012
  v03 2006 Jul 19: Added Corey's patch to avoid wrong ipmb addressing.
  v04 2006 Jul 20: Reduced the number of IPMB channels for AMC modules to 1
                   cPCI modules have 2 IPMB channels.
  v05 2007 Mar 21: Added support for AM4100 and CP6001

*/

/*
 * ipmi_oem_force.c
 *
 * MontaVista IPMI code for handling Force Computer's boards.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003 MontaVista Software Inc.
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
#include <string.h>
#include <errno.h>

#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_err.h>

#include <OpenIPMI/internal/ipmi_oem.h>
#include <OpenIPMI/internal/ipmi_int.h>

#define KONTRON_MANUFACTURER_ID 0x0003a98

/* translate a AMC GA into an I2C IPMB address */
static const unsigned char translateAdrs_amc [] =
{0, 0x72, 0x74, 0x76, 0x78, 0x7a, 0x7c, 0x7e, 0x80,
0x82, 0x84, 0x86, 0x88, 0
};

/* translate a CPCI GA into an I2C IPMB address */
static const unsigned char translateAdrs [] =
{0, 0xb0, 0xb2, 0xb4, 0xb6, 0xb8, 0xba, 0xbc, 0xbe, 0xc0, 0xc4,
0xc6, 0xc8, 0xca, 0xcc, 0xce, 0xd0, 0xd2, 0xd4, 0xd6, 0xd8,
0xda, 0xdc, 0xde, 0xe0, 0xe2, 0xe4, 0xe6, 0xe8, 0xea, 0xec, 0
};


static int
ipmb_handler_amc(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t           *msg = &rspi->msg;
    ipmi_ll_ipmb_addr_cb handler = rspi->data1;
    void                 *cb_data = rspi->data2;
    unsigned char        ipmb[MAX_IPMI_USED_CHANNELS];
    unsigned char	 geo_pos = 0;
    int                  err = 0;
    
    memset(ipmb, 0, sizeof(*ipmb));

    if (msg->data[0] != 0)
	err = IPMI_IPMI_ERR_VAL(msg->data[0]);
    else if (msg->data_len < 16)
	err = EINVAL;
    else
    {	/* BMC ? */
	if ((msg->data[6] & 0x06) == 0x06) {
	    ipmb[0] = 0x20;
	} else {
	    geo_pos = msg->data[13];
	    if (geo_pos < 1 || geo_pos > 12)
		err = EINVAL;
	    else {
		ipmb[0] = translateAdrs_amc[geo_pos];
	    }
	}
    }

    if (!err)
	ipmi->set_ipmb_addr(ipmi, ipmb, 1, 1, 0);

    if (handler)
        handler(ipmi, err, ipmb, 1, err == 0, 0, cb_data);

    return IPMI_MSG_ITEM_NOT_USED;
}

static int
kontron_ipmb_fetch_amc(ipmi_con_t           *conn,
		       ipmi_ll_ipmb_addr_cb handler,
		       void                 *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    int                          rv;
    ipmi_msgi_t                  *rspi;

    rspi = ipmi_mem_alloc(sizeof(*rspi));
    if (!rspi)
	return ENOMEM;

    /* Send the Get Device ID command to get the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = 6;
    msg.cmd = 1;
    msg.data = NULL;
    msg.data_len = 0;

    rspi->data1 = handler;
    rspi->data2 = cb_data;

    rv = conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			    ipmb_handler_amc, rspi);
    if (rv)
	ipmi_mem_free(rspi);
    return rv;    
}

static int
kontron_oem_conn_handler_amc(ipmi_con_t *conn, void *cb_data)
{
    conn->get_ipmb_addr = kontron_ipmb_fetch_amc;
    return 0;
}

static int
ipmb_handler(ipmi_con_t *ipmi, ipmi_msgi_t *rspi)
{
    ipmi_msg_t           *msg = &rspi->msg;
    ipmi_ll_ipmb_addr_cb handler = rspi->data1;
    void                 *cb_data = rspi->data2;
    unsigned char        ipmb[MAX_IPMI_USED_CHANNELS];
    unsigned char	 geo_pos = 0;
    int                  err = 0;
    
    memset(ipmb, 0, sizeof(*ipmb));

    if (msg->data[0] != 0)
	err = IPMI_IPMI_ERR_VAL(msg->data[0]);
    else if (msg->data_len < 16)
	err = EINVAL;
    else
    {	/* BMC ? */
	if ((msg->data[6] & 0x06) == 0x06) {
	    ipmb[0] = 0x20;
	    ipmb[1] = 0x20;
	} else {
	    geo_pos = msg->data[13];
	    if (geo_pos < 1 || geo_pos > 31)
		err = EINVAL;
	    else {
 		ipmb[0] = translateAdrs[geo_pos];
		ipmb[1] = ipmb[0];
	    }
	}
    }

    if (!err)
	ipmi->set_ipmb_addr(ipmi, ipmb, 2, 1, 0);

    if (handler)
        handler(ipmi, err, ipmb, 2, err == 0, 0, cb_data);

    return IPMI_MSG_ITEM_NOT_USED;
}

static int
kontron_ipmb_fetch(ipmi_con_t           *conn,
		   ipmi_ll_ipmb_addr_cb handler,
		   void                 *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    int                          rv;
    ipmi_msgi_t                  *rspi;

    rspi = ipmi_mem_alloc(sizeof(*rspi));
    if (!rspi)
	return ENOMEM;

    /* Send the Get Device ID command to get the IPMB address. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = 6;
    msg.cmd = 1;
    msg.data = NULL;
    msg.data_len = 0;

    rspi->data1 = handler;
    rspi->data2 = cb_data;

    rv = conn->send_command(conn, (ipmi_addr_t *) &si, sizeof(si), &msg,
			    ipmb_handler, rspi);
    if (rv)
	ipmi_mem_free(rspi);
    return rv;    
}

static int
kontron_oem_conn_handler(ipmi_con_t *conn, void *cb_data)
{
    conn->get_ipmb_addr = kontron_ipmb_fetch;
    return 0;
}

int
ipmi_oem_kontron_conn_init(void)
{
    int rv;
    int retrv = 0;

    /* The AM4001 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x0fa1,
					kontron_oem_conn_handler_amc,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron AM4001 OEM handler: %x",
		 rv);
    }

    /* The AM4002 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x0fa2,
					kontron_oem_conn_handler_amc,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron AM4002 OEM handler: %x",
		 rv);
    }

    /* The AM4010 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x0faa,
					kontron_oem_conn_handler_amc,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron AM4010 OEM handler: %x",
		 rv);
    }

    /* The AM4100 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x1004,
					kontron_oem_conn_handler_amc,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron AM4100 OEM handler: %x",
		 rv);
    }

    /* The CP604 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x025c,
					kontron_oem_conn_handler,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron CP604 OEM handler: %x",
		 rv);
    }

    /* The CP605 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x025d,
					kontron_oem_conn_handler,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron CP605 OEM handler: %x",
		 rv);
    }

    /* The CP6000 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x1770,
					kontron_oem_conn_handler,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron CCP6000 OEM handler: %x",
		 rv);
    }

    /* The CP6001 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x1771,
					kontron_oem_conn_handler,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron CP6001 OEM handler: %x",
		 rv);
    }

    /* The CP6006 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x1776,
					kontron_oem_conn_handler,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron CP6006 OEM handler: %x",
		 rv);
    }

    /* The CP6010 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x177A,
					kontron_oem_conn_handler,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron CP6010 OEM handler: %x",
		 rv);
    }

    /* The CP6011 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x177B,
					kontron_oem_conn_handler,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron CP6011 OEM handler: %x",
		 rv);
    }

    /* The CP6012 card */
    rv = ipmi_register_oem_conn_handler(KONTRON_MANUFACTURER_ID,
					0x177C,
					kontron_oem_conn_handler,
					NULL);
    if (rv)
    {
	retrv = rv;
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_kontron_conn.c(ipmi_oem_kontron_conn_init): "
		 "Unable to initialize the Kontron CP6012 OEM handler: %x",
		 rv);
    }

    return retrv;
}

void
ipmi_oem_kontron_conn_shutdown(void)
{
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x0fa1);
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x0fa2);/* AM4002 */
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x0faa);/* AM4010 */
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x1004);/* AM4100 */
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x025c);
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x025d);
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x1770);
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x1771);/* CP60001 */
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x1776);
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x177A);
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x177B);
    ipmi_deregister_oem_handler(KONTRON_MANUFACTURER_ID, 0x177C);/* CP6012 */
}


#if 0
/* If you include this as a module under Linux, you can use the
   following code to initialize it.  Otherwise, something has to call
   ipmi_oem_kontron_conn_init(). */
static void (*const __init_patch_debug[1])                                    \
   (void) __attribute__ ((section(".ctors"))) = { ipmi_oem_kontron_conn_init };
#endif
