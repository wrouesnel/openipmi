/*
 * bmc_transport.c
 *
 * MontaVista IPMI code for emulating a MC.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003,2012 MontaVista Software Inc.
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
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include "bmc.h"

#include <errno.h>
#include <string.h>

#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>

static void
handle_ipmi_set_lan_config_parms(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len,
				 void          *cb_data)
{
    unsigned char lchan;
    channel_t *chan;

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    lchan = msg->data[0];
    if (lchan == 0xe)
	lchan = msg->channel;
    else if (lchan >= IPMI_MAX_CHANNELS) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->channels[lchan]) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }
    chan = mc->channels[lchan];

    if (!chan->set_lan_parms) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    chan->set_lan_parms(chan, msg, rdata, rdata_len);
}

static void
handle_ipmi_get_lan_config_parms(lmc_data_t    *mc,
				 msg_t         *msg,
				 unsigned char *rdata,
				 unsigned int  *rdata_len,
				 void          *cb_data)
{
    unsigned char lchan;
    channel_t *chan;

    if (msg->len < 4) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    lchan = msg->data[0];
    if (lchan == 0xe)
	lchan = msg->channel;
    else if (lchan >= IPMI_MAX_CHANNELS) {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }

    if (!mc->channels[lchan]) {
	rdata[0] = IPMI_NOT_PRESENT_CC;
	*rdata_len = 1;
	return;
    }

    chan = mc->channels[lchan];

    if (!chan->get_lan_parms) {
	rdata[0] = IPMI_INVALID_CMD_CC;
	*rdata_len = 1;
	return;
    }

    chan->get_lan_parms(chan, msg, rdata, rdata_len);
}

static void
handle_set_sol_config_parms(lmc_data_t    *mc,
			    msg_t         *msg,
			    unsigned char *rdata,
			    unsigned int  *rdata_len,
			    void          *cb_data)
{
    unsigned char err = 0;
    unsigned char val;
    int write_config = 0;
    ipmi_sol_t *sol = &mc->sol;

    if (!mc->sol.configured) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    /*
     * There is a channel in this message, but as far as I can tell,
     * it is completely without point.  The data is generic to the
     * management controller.  So just ignore it.
     */

    switch (msg->data[1]) {
    case 0:
	switch (msg->data[2] & 0x3) {
	case 0:
	    if (sol->set_in_progress) {
		/* Rollback */
		memcpy(&mc->sol.solparm, &mc->sol.solparm_rollback,
		       sizeof(solparm_t));
		write_config = 1;
	    }
	    break;

	case 1:
	    if (sol->set_in_progress)
		err = 0x81; /* Another user is writing. */
	    else {
		/* Save rollback data */
		memcpy(&mc->sol.solparm_rollback, &mc->sol.solparm,
		       sizeof(solparm_t));
		sol->set_in_progress = 1;
	    }
	    break;

	case 2:
	    sol->set_in_progress = 0;
	    break;

	case 3:
	    err = IPMI_INVALID_DATA_FIELD_CC;
	}
	break;

    case 1:
	sol->solparm.enabled = msg->data[2] & 1;
	write_config = 1;
	break;

    case 5:
	val = msg->data[2] & 0xf;
	if ((val < 6) || (val > 0xa)) {
	    err = IPMI_INVALID_DATA_FIELD_CC;
	} else {
	    sol->solparm.bitrate_nonv = val;
	    write_config = 1;
	}
	break;

    case 6:
	val = msg->data[2] & 0xf;
	if ((val < 6) || (val > 0xa)) {
	    err = IPMI_INVALID_DATA_FIELD_CC;
	} else {
	    sol->solparm.bitrate = val;
	    if (sol->update_bitrate)
		sol->update_bitrate(mc);
	}
	break;

    default:
	err = 0x80; /* Parm not supported */
    }

    if (write_config)
	write_sol_config(mc);

    rdata[0] = err;
    *rdata_len = 1;
}

static void
handle_get_sol_config_parms(lmc_data_t    *mc,
			    msg_t         *msg,
			    unsigned char *rdata,
			    unsigned int  *rdata_len,
			    void          *cb_data)
{
    ipmi_sol_t *sol = &mc->sol;
    unsigned char databyte = 0;

    if (!mc->sol.configured) {
	handle_invalid_cmd(mc, rdata, rdata_len);
	return;
    }

    if (msg->len < 4) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    /*
     * There is a channel in this message, but as far as I can tell,
     * it is completely without point.  The data is generic to the
     * management controller.  So just ignore it.
     */

    switch (msg->data[1]) {
    case 0:
	databyte = sol->set_in_progress;
	break;

    case 1:
	databyte = sol->solparm.enabled;
	break;

    case 5:
	databyte = sol->solparm.bitrate_nonv;
	break;

    case 6:
	databyte = sol->solparm.bitrate;
	break;

    default:
	rdata[0] = 0x80; /* Parm not supported */
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = 0x11;
    rdata[2] = databyte;
    *rdata_len = 3;
}

cmd_handler_f transport_netfn_handlers[256] = {
    [IPMI_SET_LAN_CONFIG_PARMS_CMD] = handle_ipmi_set_lan_config_parms,
    [IPMI_GET_LAN_CONFIG_PARMS_CMD] = handle_ipmi_get_lan_config_parms,
    [IPMI_SET_SOL_CONFIGURATION_PARAMETERS] = handle_set_sol_config_parms,
    [IPMI_GET_SOL_CONFIGURATION_PARAMETERS] = handle_get_sol_config_parms
};
