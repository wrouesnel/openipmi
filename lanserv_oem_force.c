/*
 * lanserv_force_oem.c
 *
 * MontaVista IPMI IPMI LAN code for OEM Force Computers board handling
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

#include <OpenIPMI/lanserv.h>

typedef struct force_oem_data_s
{
    unsigned char slave_addr;
    unsigned char curr_addr;
} force_oem_data_t;

static int
force_rsp_handler(lan_data_t *lan, msg_t *msg,
		  session_t *session, rsp_msg_t *rsp)
{
    unsigned char new_addr;

    if (rsp->netfn == 0x31) {
	/* A force OEM response. */
	force_oem_data_t *fdata = lan->oem_data;

	switch (rsp->cmd)
	{
	    case 3:
		/* A response to a change mode. */

		/* Ignore errors. */
		if (rsp->data_len < 1)
		    return 0;
		if (rsp->data[0] != 0)
		    return 0;

		/* See what it was changed to. */
		if (msg->data[0] == 0)
		    /* Changed to master, address is 0x20 */
		    new_addr = 0x20;
		else
		    new_addr = fdata->slave_addr;

		if (new_addr != fdata->curr_addr) {
		    fdata->curr_addr = fdata->slave_addr;
		    lan->log(INFO, NULL,
			     "Change Force MC address to 0x%x", new_addr);
		    if (lan->ipmb_addr_change)
			lan->ipmb_addr_change(lan, fdata->curr_addr);
		}
		break;

	    case 4:
		/* A request for the IPMB address. */
		
		/* Ignore errors. */
		if (rsp->data_len < 4)
		    return 0;
		if (rsp->data[0] != 0)
		    return 0;

		fdata->slave_addr = rsp->data[3];
		if (fdata->curr_addr != rsp->data[2]) {
		    fdata->curr_addr = rsp->data[2];
		    if (lan->ipmb_addr_change)
			lan->ipmb_addr_change(lan, fdata->curr_addr);
		}

		return msg->oem_data;
	}
    }

    return 0;
}

static int
force_check_permitted(unsigned char priv,
		      unsigned char netfn,
		      unsigned char cmd)
{
    int req_priv = IPMI_PRIVILEGE_ADMIN;

    if (netfn != 0x30)
	return IPMI_PRIV_INVALID;

    switch (cmd)
    {
	case 3:
	    req_priv = IPMI_PRIVILEGE_OPERATOR;
	    break;

	case 4:
	    req_priv = IPMI_PRIVILEGE_USER;
	    break;

	case 5:
	    req_priv = IPMI_PRIVILEGE_USER;
	    break;

	case 6:
	    req_priv = IPMI_PRIVILEGE_OPERATOR;
	    break;
    }

    if (priv >= req_priv)
	return IPMI_PRIV_PERMITTED;
    else
	return IPMI_PRIV_DENIED;
}

static force_oem_data_t force_data =
{
    .slave_addr = 0,
    .curr_addr  = 0,
};

static void
force_oem_installer(lan_data_t *lan, void *cb_data)
{
    lan->oem_handle_rsp = force_rsp_handler;
    lan->oem_check_permitted = force_check_permitted;
    lan->oem_data = &force_data;

    /* Set a command to get the current address. */
    ipmi_oem_send_msg(lan, 0x30, 4, NULL, 0, 1);
}

static oem_handler_t force_735_oem =
{
    .manufacturer_id = 0x000e48,
    .product_id      = 0x0804,
    .handler         = force_oem_installer,
    .cb_data         = NULL,
};

static oem_handler_t force_740_oem =
{
    .manufacturer_id = 0x000e48,
    .product_id      = 0x0808,
    .handler         = force_oem_installer,
    .cb_data         = NULL,
};

static oem_handler_t force_786_oem =
{
    .manufacturer_id = 0x000e48,
    .product_id      = 0x0810,
    .handler         = force_oem_installer,
    .cb_data         = NULL,
};

static oem_handler_t force_550_oem =
{
    .manufacturer_id = 0x000e48,
    .product_id      = 0x0880,
    .handler         = force_oem_installer,
    .cb_data         = NULL,
};

static oem_handler_t force_560_oem =
{
    .manufacturer_id = 0x000e48,
    .product_id      = 0x0888,
    .handler         = force_oem_installer,
    .cb_data         = NULL,
};

static oem_handler_t force_690_oem =
{
    .manufacturer_id = 0x000e48,
    .product_id      = 0x0900,
    .handler         = force_oem_installer,
    .cb_data         = NULL,
};

static oem_handler_t force_695_oem =
{
    .manufacturer_id = 0x000e48,
    .product_id      = 0x0904,
    .handler         = force_oem_installer,
    .cb_data         = NULL,
};


void
init_oem_force(void)
{
    ipmi_register_oem(&force_735_oem);
    ipmi_register_oem(&force_740_oem);
    ipmi_register_oem(&force_786_oem);
    ipmi_register_oem(&force_550_oem);
    ipmi_register_oem(&force_560_oem);
    ipmi_register_oem(&force_690_oem);
    ipmi_register_oem(&force_695_oem);
}

#if 0
/* If you include this as a module under Linux, you can use the
   following code to initialize it.  Otherwise, something has to call
   init_oem_force(). */
static void (*const __init_patch_debug[1])                                    \
   (void) __attribute__ ((section(".ctors"))) = { init_oem_force };
#endif
