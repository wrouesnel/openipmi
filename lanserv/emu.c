/*
 * emu.c
 *
 * MontaVista IPMI code for emulating a BMC.
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
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include <string.h>
#include <stdlib.h>
#include <stdint.h>

#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_msgbits.h>

#include "emu.h"

/* Deal with multi-byte data, IPMI (little-endian) style. */
static unsigned int ipmi_get_uint16(uint8_t *data)
{
    return (data[0]
	    | (data[1] << 8));
}

static void ipmi_set_uint16(uint8_t *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
}

static unsigned int ipmi_get_uint32(uint8_t *data)
{
    return (data[0]
	    | (data[1] << 8)
	    | (data[2] << 16)
	    | (data[3] << 24));
}

static void ipmi_set_uint32(uint8_t *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
    data[2] = (val >> 16) & 0xff;
    data[3] = (val >> 24) & 0xff;
}

typedef struct sel_entry_s
{
    unsigned char      data[16];
    struct sel_entry_s *next;
} sel_entry_t;

typedef struct sel_s
{
    sel_entry_t   *entries;
    int           count;
    int           max_count;
    uint32_t      last_add_time;
    uint32_t      last_erase_time;
    unsigned char flags;
    uint16_t      reservation;
} sel_t;

struct emu_data_s
{
    /* Get Device Id contents. */
    unsigned char device_id;       /* byte 2 */
    unsigned char has_device_sdrs; /* byte 3, bit 7 */
    unsigned char device_revision; /* byte 3, bits 0-6 */
    unsigned char major_fw_rev;    /* byte 4, bits 0-6 */
    unsigned char minor_fw_rev;    /* byte 5 */
    unsigned char device_support;  /* byte 7 */
    unsigned char mfg_id[3];	   /* bytes 8-10 */
    unsigned char product_id[2];   /* bytes 11-12 */

    sel_t sel;

    /* The time offset to calculate the current timestamp. */
    time_t start_sel_time;

    emu_data_t *ipmb[128];
};

/*
 * SEL handling commands.
 */

static void
handle_invalid_cmd(emu_data_t    *emu,
		   unsigned char *rdata,
		   unsigned int  *rdata_len)
{
    rdata[0] = IPMI_INVALID_CMD_CC;
    *rdata_len = 1;
}

static int
check_msg_length(ipmi_msg_t    *msg,
		 unsigned int  len,
		 unsigned char *rdata,
		 unsigned int  *rdata_len)
{
    if (msg->data_len < len) {
	rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
	*rdata_len = 1;
	return 1;
    }

    return 0;
}

static void
handle_get_sel_info(emu_data_t    *emu,
		    ipmi_msg_t    *msg,
		    unsigned char *rdata,
		    unsigned int  *rdata_len)
{
    if (!(emu->device_support & (1 << 2))) {
	handle_invalid_cmd(emu, rdata, rdata_len);
	return;
    }

    memset(rdata, 0, 15);
    rdata[1] = 0x51;
    ipmi_set_uint16(rdata+2, emu->sel.count);
    ipmi_set_uint16(rdata+4, (emu->sel.max_count - emu->sel.count) * 16);
    ipmi_set_uint32(rdata+6, emu->sel.last_add_time);
    ipmi_set_uint32(rdata+10, emu->sel.last_erase_time);
    rdata[14] = emu->sel.flags;

    /* Clear the overflow flag. */
    /* FIXME - is this the right way to clear this?  There doesn't
       seem to be another way. */
    emu->sel.flags &= ~0x80;

    *rdata_len = 15;
}

static void
handle_reserve_sel(emu_data_t    *emu,
		   ipmi_msg_t    *msg,
		   unsigned char *rdata,
		   unsigned int  *rdata_len)
{
    if (!(emu->device_support & (1 << 2))) {
	handle_invalid_cmd(emu, rdata, rdata_len);
	return;
    }

    emu->sel.reservation++;
    if (emu->sel.reservation == 0)
	emu->sel.reservation++;
    rdata[0] = 0;
    ipmi_set_uint16(rdata+1, emu->sel.reservation);
    *rdata_len = 3;
}

static void
handle_get_sel_entry(emu_data_t    *emu,
		     ipmi_msg_t    *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    if (!(emu->device_support & (1 << 2))) {
	handle_invalid_cmd(emu, rdata, rdata_len);
	return;
    }

    if (check_msg_length(msg, 6, rdata, rdata_len))
	return;

    reservation = msg->data[8]
}

static void
handle_storage_netfn(emu_data_t    *emu,
		     ipmi_msg_t    *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    switch(msg->cmd) {
	case IPMI_GET_SEL_INFO_CMD:
	    handle_get_sel_info(emu, msg, rdata, rdata_len);
	    break;

	default:
	    handle_invalid_cmd(emu, rdata, rdata_len);
	    break;
    }
}

static void
handle_get_device_id(emu_data_t    *emu,
		     ipmi_msg_t    *msg,
		     unsigned char *rdata,
		     unsigned int  *rdata_len)
{
    memset(rdata, 0, 12);
    rdata[1] = emu->device_id;
    rdata[2] = ((emu->has_device_sdrs << 0x7)
		|| (emu->device_revision & 0xf));
    rdata[3] = emu->major_fw_rev & 0x7f;
    rdata[4] = emu->minor_fw_rev;
    rdata[5] = 0x51;
    rdata[6] = emu->device_support;
    memcpy(rdata+7, emu->mfg_id, 3);
    memcpy(rdata+10, emu->product_id, 1);
    *rdata_len = 12;
}

static void
handle_app_netfn(emu_data_t    *emu,
		 ipmi_msg_t    *msg,
		 unsigned char *rdata,
		 unsigned int  *rdata_len)
{
    switch(msg->cmd) {
	case IPMI_GET_DEVICE_ID_CMD:
	    handle_get_device_id(emu, msg, rdata, rdata_len);
	    break;

	default:
	    handle_invalid_cmd(emu, rdata, rdata_len);
	    break;
    }
}

void
ipmi_emu_register_ipmb(emu_data_t    *emu,
		       unsigned char slave_addr,
		       emu_data_t    *semu)
{
    emu->ipmb[slave_addr>>1] = semu;
}

void
ipmi_emu_handle_msg(emu_data_t     *emu,
		    emu_msgparms_t *parms,
		    unsigned char  lun,
		    ipmi_msg_t     *msg,
		    unsigned char  *rdata,
		    unsigned int   *rdata_len)
{
    if (msg->cmd == IPMI_SEND_MSG_CMD) {
	/* Encapsulated IPMB, do special handling. */
	unsigned char slave;
	ipmi_msg_t    smsg;
	unsigned char *data;
	unsigned int  data_len;
	emu_data_t    *semu;

	if (check_msg_length(msg, 8, rdta, rdata_len))
	    return;
	if ((msg->data[0] & 0x3f) != 0) {
	    rdata[0] = IPMI_INVALID_DATA_FIELD_CC;
	    *rdata_len = 1;
	    return;
	}

	data = msg->data + 1;
	data_len = msg->data_len - 1;
	if (data[0] == 0) {
	    /* Broadcast, just skip the first byte, but check len. */
	    data++;
	    data_len--;
	    if (data_len < 8) {
		rdata[0] = IPMI_REQUEST_DATA_LENGTH_INVALID_CC;
		*rdata_len = 1;
		return;
	    }
	}
	slave = data[0];
	semu = emu->ipmb[slave >> 1];
	if (!semu) {
	    rdata[0] = 0x83; /* NAK on Write */
	    *rdata_len = 1;
	    return;
	}

	smsg.netfn = data[1] >> 2;
	lun = data[1] & 0x3;
	*(parms->netfn) = smsg.netfn;
	*(parms->rqSA) = data[3];
	*(parms->seq) = data[4] >> 2;
	*(parms->rqLun) = data[4] & 0x3;
	*(parms->cmd) = data[5];
	smsg.cmd = data[5];
	smsg.data = data + 6;
	smsg.data_len = data_len - 7; /* Subtract off the header and
					 the end checksum */

	/* Let the sub-emulator handle the message. */
	ipmi_emu_handle_msg(semu, parms, lun, &smsg, rdata, rdata_len);
    } else {
	switch (msg->netfn) {
	    case IPMI_APP_NETFN:
		handle_app_netfn(emu, msg, rdata, rdata_len);
		break;

	    case IPMI_STORAGE_NETFN:
		handle_storage_netfn(emu, msg, rdata, rdata_len);
		break;

	    default:
		handle_invalid_cmd(emu, rdata, rdata_len);
		break;
	}
    }
}

emu_data_t *
ipmi_emu_alloc(void)
{
    emu_data_t *data = malloc(sizeof(*data));
    if (data)
	memset(data, 0, sizeof(*data));
    return data;
}
