/*
 * bmc_chassis.c
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
#include <OpenIPMI/extcmd.h>

static extcmd_map_t boot_map[] = {
    { 0, "none" },
    { 1, "pxe" },
    { 2, "default" },
    { 5, "cdrom" },
    { 6, "bios" },
    { 0, NULL }
};

/* Matches the CHASSIS_CONTROL defines. */
static extcmd_info_t chassis_prog[] = {
    { "power", extcmd_int, NULL, 0 },
    { "reset", extcmd_int, NULL, 0 },
    { "boot", extcmd_uchar, boot_map, 0 },
    { "boot", extcmd_uchar, boot_map, 0 }, // dup'd for boot info ack
    { "shutdown", extcmd_int, NULL, 0 },
    { "identify", extcmd_ident, NULL, 0 },
};

static int
set_power(lmc_data_t *mc, int pval)
{
    int rv = 0;

    if (mc->chassis_control_set_func) {
	unsigned char val = !!pval;
	rv = mc->chassis_control_set_func(mc, CHASSIS_CONTROL_POWER, &val,
					  mc->chassis_control_cb_data);
    } else if (mc->chassis_control_prog) {
	int val = !!pval;
	if (extcmd_setvals(mc->sysinfo, &val, mc->chassis_control_prog,
			   &chassis_prog[CHASSIS_CONTROL_POWER], NULL, 1)) 
	    rv = EINVAL;
    } else if (HW_OP_CAN_POWER(mc->channels[15])) {
	if (pval)
	    mc->channels[15]->hw_op(mc->channels[15], HW_OP_POWERON);
	else
	    mc->channels[15]->hw_op(mc->channels[15], HW_OP_POWEROFF);
    } else
	return ENOTSUP;
    return rv;
}

static void
power_timeout(void *cb_data)
{
    lmc_data_t *mc = cb_data;

    mc->sysinfo->free_timer(mc->power_timer);
    mc->power_timer = NULL;
    set_power(mc, 1);
}

int
start_poweron_timer(lmc_data_t *mc)
{
    int rv;
    struct timeval tv = { 1, 0 };

    if (mc->power_timer)
	return 0;

    rv = mc->sysinfo->alloc_timer(mc->sysinfo, power_timeout,
				  mc, &mc->power_timer);
    if (rv)
	return rv;
    
    mc->sysinfo->start_timer(mc->power_timer, &tv);
    return 0;
}

static void
handle_get_chassis_capabilities(lmc_data_t    *mc,
				msg_t         *msg,
				unsigned char *rdata,
				unsigned int  *rdata_len,
				void          *cb_data)
{
    rdata[0] = 0;
    rdata[1] = 0;
    rdata[2] = mc->sysinfo->bmc_ipmb;
    rdata[3] = mc->sysinfo->bmc_ipmb;
    rdata[4] = mc->sysinfo->bmc_ipmb;
    rdata[5] = mc->sysinfo->bmc_ipmb;
}

static void
handle_get_chassis_status(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len,
			  void          *cb_data)
{
    rdata[0] = 0;
    if (mc->chassis_control_get_func) {
	unsigned char val;
	int rv;
	rv = mc->chassis_control_get_func(mc, CHASSIS_CONTROL_POWER, &val,
					  mc->chassis_control_cb_data);
	if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	rdata[1] = val;
    } else if (mc->chassis_control_prog) {
	int val;
	if (extcmd_getvals(mc->sysinfo, &val, mc->chassis_control_prog,
			   &chassis_prog[CHASSIS_CONTROL_POWER], 1)) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	rdata[1] = val;
    } else if (mc->startcmd.vmpid) {
	rdata[1] = 1;
    } else if (HW_OP_CAN_POWER(mc->channels[15])) {
	int rv = mc->channels[15]->hw_op(mc->channels[15], HW_OP_CHECK_POWER);
	rdata[1] = rv > 0;
    }
    rdata[2] = 0;
    rdata[3] = 0;
    *rdata_len = 4;
}

static void
handle_chassis_control(lmc_data_t    *mc,
		       msg_t         *msg,
		       unsigned char *rdata,
		       unsigned int  *rdata_len,
		       void          *cb_data)
{
    int rv;

    if (msg->len < 1) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    *rdata_len = 1;

    switch(msg->data[0] & 0xf) {
    case 0: /* power down */
	rv = set_power(mc, 0);
	if (rv == ENOTSUP)
	    goto no_support;
	else if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	break;

    case 1: /* power up */
	rv = set_power(mc, 1);
	if (rv == ENOTSUP)
	    goto no_support;
	else if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	break;

    case 2: /* power cycle */
	rv = start_poweron_timer(mc);
	if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	rv = set_power(mc, 0);
	if (rv == ENOTSUP)
	    goto no_support;
	else if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
	break;

    case 3: /* hard reset */
	if (mc->chassis_control_set_func) {
	    int rv;
	    unsigned char val = 1;
	    rv = mc->chassis_control_set_func(mc, CHASSIS_CONTROL_RESET, &val,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    int val = 1;
	    if (extcmd_setvals(mc->sysinfo, &val, mc->chassis_control_prog,
			       &chassis_prog[CHASSIS_CONTROL_RESET], NULL, 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (HW_OP_CAN_RESET(mc->channels[15]))
	    mc->channels[15]->hw_op(mc->channels[15], HW_OP_RESET);
	else
	    goto no_support;
	break;

    case 5: /* initiate soft-shutdown via overtemp */
	if (mc->chassis_control_set_func) {
	    int rv;
	    unsigned char val = 1;
	    rv = mc->chassis_control_set_func(mc,
					      CHASSIS_CONTROL_GRACEFUL_SHUTDOWN,
					      &val,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    int val = 1;
	    if (extcmd_setvals(mc->sysinfo, &val, mc->chassis_control_prog,
			       &chassis_prog[CHASSIS_CONTROL_GRACEFUL_SHUTDOWN],
			       NULL, 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (HW_OP_CAN_GRACEFUL_SHUTDOWN(mc->channels[15]))
	    mc->channels[15]->hw_op(mc->channels[15], HW_OP_GRACEFUL_SHUTDOWN);
	else
	    goto no_support;
	break;

    case 4: /* pulse diag interrupt */
    no_support:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	return;
    }
}

static void
handle_chassis_identify(lmc_data_t    *mc,
			  msg_t         *msg,
			  unsigned char *rdata,
			  unsigned int  *rdata_len,
			  void          *cb_data)
{
    unsigned char val[2];

    rdata[0] = 0;
    memset(val, 0, sizeof(val));

    if (msg->len == 0)
        val[0] = 0xf; /* default 15 seconds */
    else
        val[0] = msg->data[0]; /* interval */

    if (msg->len > 1) /* force flag is set */
        val[1] = msg->data[1] & 0x1;

    if (mc->chassis_control_set_func) {
	int rv;
	rv = mc->chassis_control_set_func(mc, CHASSIS_CONTROL_IDENTIFY,
					  val, mc->chassis_control_cb_data);
	if (rv) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
    } else if (mc->chassis_control_prog) {
	if (extcmd_setvals(mc->sysinfo, val, mc->chassis_control_prog,
			   &chassis_prog[CHASSIS_CONTROL_IDENTIFY], NULL, 1)) {
	    rdata[0] = IPMI_UNKNOWN_ERR_CC;
	    *rdata_len = 1;
	    return;
	}
    } else {
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
    }
}

static void
set_system_boot_options(lmc_data_t    *mc,
			msg_t         *msg,
			unsigned char *rdata,
			unsigned int  *rdata_len,
			void          *cb_data)
{
    unsigned char val;

    if (msg->len < 1) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    *rdata_len = 1;

    switch (msg->data[0] & 0x3f) {
    case 1:
	if (msg->len < 2) {
	    rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	    *rdata_len = 1;
	    return;
	}
	switch (msg->data[2] & 0x3) {
	case 0:
	case 1:
	    /* Just ignore this for now. */
	    break;

	default:
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    break;
	}
	break;

    case 4: /* Boot Info Ack */
	if (msg->len < 3) {
	    rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	    *rdata_len = 1;
	    return;
	}

	if (mc->chassis_control_set_func) {
	    int rv;
	    rv = mc->chassis_control_set_func(mc, CHASSIS_CONTROL_BOOT_INFO_ACK,
					      msg->data + 1,
					      mc->chassis_control_cb_data);

	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    if (extcmd_getvals(mc->sysinfo, &val, mc->chassis_control_prog,
			    &chassis_prog[CHASSIS_CONTROL_BOOT_INFO_ACK], 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	}
	break;

    case 5: /* Boot flags */
	if (msg->len < 6) {
	    rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	    *rdata_len = 1;
	    return;
	}
	val = (msg->data[2] >> 2) & 0xf;
	
	if (mc->chassis_control_set_func) {
	    int rv;
	    rv = mc->chassis_control_set_func(mc, CHASSIS_CONTROL_BOOT, &val,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    if (extcmd_setvals(mc->sysinfo, &val, mc->chassis_control_prog,
			       &chassis_prog[CHASSIS_CONTROL_BOOT], NULL, 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	}
	break;

    default:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	break;
    }
}

static void
get_system_boot_options(lmc_data_t    *mc,
			msg_t         *msg,
			unsigned char *rdata,
			unsigned int  *rdata_len,
			void          *cb_data)
{
    unsigned char val;

    if (msg->len < 3) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return;
    }

    rdata[0] = 0;
    rdata[1] = 1;
    rdata[2] = msg->data[0] & 0x3f;
    *rdata_len = 3;

    switch (msg->data[0] & 0x3f) {
    case 1:
	/* Dummy this out for now */
	rdata[3] = 0;
	*rdata_len = 4;
	break;

    case 4: /* Boot Info Ack */
	if (mc->chassis_control_set_func) {
	    int rv;
	    rv = mc->chassis_control_get_func(mc, CHASSIS_CONTROL_BOOT,
					      rdata + 3,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	    *rdata_len = 5;
	}
	break;

    case 5: /* Boot flags */
	if (mc->chassis_control_set_func) {
	    int rv;
	    rv = mc->chassis_control_get_func(mc, CHASSIS_CONTROL_BOOT, &val,
					      mc->chassis_control_cb_data);
	    if (rv) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else if (mc->chassis_control_prog) {
	    if (extcmd_getvals(mc->sysinfo, &val, mc->chassis_control_prog,
			       &chassis_prog[CHASSIS_CONTROL_BOOT], 1)) {
		rdata[0] = IPMI_UNKNOWN_ERR_CC;
		*rdata_len = 1;
		return;
	    }
	} else {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}

	rdata[3] = 0;
	rdata[4] = val << 2;
	rdata[5] = 0;
	rdata[6] = 0;
	rdata[7] = 0;
	*rdata_len = 8;
	break;

    default:
	rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	*rdata_len = 1;
	break;
    }
}

cmd_handler_f chassis_netfn_handlers[256] = {
    [IPMI_GET_CHASSIS_CAPABILITIES_CMD] = handle_get_chassis_capabilities,
    [IPMI_GET_CHASSIS_STATUS_CMD] = handle_get_chassis_status,
    [IPMI_CHASSIS_CONTROL_CMD] = handle_chassis_control,
    [IPMI_SET_SYSTEM_BOOT_OPTIONS_CMD] = set_system_boot_options,
    [IPMI_GET_SYSTEM_BOOT_OPTIONS_CMD] = get_system_boot_options,
    [IPMI_CHASSIS_IDENTIFY_CMD] = handle_chassis_identify
};

