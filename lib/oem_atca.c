/*
 * oem_atca.c
 *
 * OEM code to make ATCA chassis fit into OpenIPMI.
 *
 *  (C) 2004 MontaVista Software, Inc.
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
#include <string.h>
#include <errno.h>
#include <math.h>
#include <stdio.h> /* For sprintf */
#include <OpenIPMI/ipmi_conn.h>
#include <OpenIPMI/ipmi_oem.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_sensor.h>
#include <OpenIPMI/ipmi_control.h>
#include <OpenIPMI/ipmi_entity.h>
#include <OpenIPMI/ipmi_addr.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_msgbits.h>

#define PICMG_MFG_ID	0x315a

/* PICMG Site type */
#define PICMG_SITE_TYPE_PICMG_BOARD		0
#define PICMG_SITE_TYPE_POWER_ENTRY_MODULE	1
#define PICMG_SITE_TYPE_SHELF_FRU_INFO		2
#define PICMG_SITE_TYPE_DEDICATED_SHMC		3
#define PICMG_SITE_TYPE_FAN_TRAY		4
#define PICMG_SITE_TYPE_FAN_FILTER_TRAY		5
#define PICMG_SITE_TYPE_ALARM			6
#define PICMG_SITE_TYPE_PICMG_MODULE		7
#define PICMG_SITE_TYPE_PMC			8
#define PICMG_SITE_TYPE_READ_TRANSITION_MODULE	9

/* Address key types, mainly for get address info. */
#define PICMG_ADDRESS_KEY_HARDWARE	0
#define PICMG_ADDRESS_KEY_IPMB_0	1
#define PICMG_ADDRESS_KEY_PHYSICAL	3

/* PICMG Commands */
#define PICMG_NETFN				0x2c
#define PICMG_ID				0
#define PICMG_CMD_GET_ADDRESS_INFO		1

typedef struct atca_address_s
{
    unsigned char hw_address;
    unsigned char site_num;
    unsigned char site_type;
} atca_address_t;

typedef struct atca_board_s
{
    unsigned char ipmb_addr;
    ipmi_entity_t *entity;
} atca_board_t;

typedef struct atca_info_s
{
    ipmi_domain_t *domain;
    unsigned char shelf_fru_ipmb;
    unsigned char shelf_fru_device_id;
    ipmi_fru_t    *shelf_fru;

    unsigned char        shelf_address[40];
    enum ipmi_str_type_e shelf_address_type;
    unsigned int         shelf_address_len;

    unsigned int   num_addresses;
    atca_address_t *addresses;
} atca_info_t;


static void
shelf_fru_fetched(ipmi_fru_t *fru, int err, void *cb_data)
{
    atca_info_t   *info = cb_data;
    ipmi_domain_t *domain = info->domain;
    unsigned int  count;
    int           found;
    int           i, j;

    if (err) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(shelf_fru_fetched): "
		 "Error getting FRU information: 0x%x",
		 DOMAIN_NAME(domain), err);
	goto out;
    }

    /* We got the shelf FRU info, now hunt through it for the address
       table. */
    found = 0;
    count = ipmi_fru_get_num_multi_records(fru);
    for (i=0; i<count; i++) {
	unsigned char type;
	unsigned char ver;
	unsigned int  len;
	unsigned char *data;
	unsigned int  mfg_id;
	unsigned char *p;
	    
	if ((ipmi_fru_get_multi_record_type(fru, i, &type) != 0)
	    || (ipmi_fru_get_multi_record_type(fru, i, &ver) != 0)
	    || (ipmi_fru_get_multi_record_data_len(fru, i, &len) != 0))
	    continue;

	if ((type != 0xc0) || (ver != 2) || (len < 27))
	    continue;

	data = ipmi_mem_alloc(len);
	if (ipmi_fru_get_multi_record_data(fru, i, data, &len) != 0) {
	    ipmi_mem_free(data);
	    continue;
	}

	mfg_id = data[0] | (data[1] << 8) | (data[2] << 16);
	if (mfg_id != PICMG_MFG_ID)
	    continue;

	if (data[4] != 0x10) /* Address table record id */
	    continue;

	if (data[5] != 0) /* We only know version 0 */
	    continue;

	if (len < (27 + (3 * data[26])))
	    /* length does not meet the minimum possible length. */
	    continue;

	info->shelf_address_len
	    = ipmi_get_device_string(data+6, 21,
				     info->shelf_address, 0,
				     &info->shelf_address_type,
				     sizeof(info->shelf_address));

	info->addresses = ipmi_mem_alloc(sizeof(atca_address_t) * data[26]);
	if (!info->addresses)
	    goto out;

	info->num_addresses = data[26];
	p = data+27;
	for (j=0; j<data[26]; j++, p += 3) {
	    info->addresses[j].hw_address = p[0];
	    info->addresses[j].site_num = p[1];
	    info->addresses[j].site_type = p[2];
	}

	ipmi_mem_free(data);
    }

    count = 0;
    for (i=0; i<info->num_addresses; i++) {
	
    }

 out:
    return;
}

static void
atca_oem_data_destroyer(ipmi_domain_t *domain, void *oem_data)
{
    atca_info_t *info = oem_data;

    ipmi_mem_free(info);
}

static void
set_up_atca_domain(ipmi_domain_t *domain, ipmi_msg_t *get_addr)
{
    atca_info_t *info;
    int         rv;

    if (get_addr->data_len < 8) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_domain): "
		 "ATCA get address response not long enough",
		 DOMAIN_NAME(domain));
	goto out;
    }

    info = ipmi_mem_alloc(sizeof(*info));
    if (!info) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "%soem_atca.c(set_up_atca_domain): "
		 "Could not allocate ATCA information structure",
		 DOMAIN_NAME(domain));
	goto out;
    }
    memset(info, 0, sizeof(*info));

    info->domain = domain;
    info->shelf_fru_ipmb = get_addr->data[3];
    info->shelf_fru_device_id = get_addr->data[5];

    rv = ipmi_fru_alloc(domain,
			1,
			info->shelf_fru_ipmb,
			info->shelf_fru_device_id,
			0,
			0,
			0,
			shelf_fru_fetched,
			info,
			&info->shelf_fru);
    if (rv) {
	ipmi_log(IPMI_LOG_SEVERE,
		 "oem_atca.c(set_up_atca_domain): "
		 "Error allocating fru information: 0x%x", rv);
	ipmi_mem_free(info);
	goto out;
    }

    ipmi_domain_set_oem_data(domain, info, atca_oem_data_destroyer);

 out:
    return;
}

static void
check_if_atca_cb(ipmi_domain_t *domain,
		 ipmi_addr_t   *addr,
		 unsigned int  addr_len,
		 ipmi_msg_t    *msg,
		 void          *rsp_data1,
		 void          *rsp_data2)
{
    ipmi_domain_oem_check_done done = rsp_data1;

    if (!domain)
	return;

    if (msg->data[0] == 0) {
	/* It's an ATCA system, set it up */
	set_up_atca_domain(domain, msg);
    }
    done(domain, rsp_data2);
}

int
check_if_atca(ipmi_domain_t              *domain,
	      ipmi_domain_oem_check_done done,
	      void                       *cb_data)
{
    ipmi_system_interface_addr_t si;
    ipmi_msg_t                   msg;
    unsigned char 		 data[5];

    /* Send the ATCA Get Address Info command to get the shelf FRU info. */
    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = 0xf;
    si.lun = 0;
    msg.netfn = PICMG_NETFN;
    msg.cmd = PICMG_CMD_GET_ADDRESS_INFO;
    data[0] = PICMG_ID;
    data[1] = 0; /* Ignored for physical address */
    data[2] = PICMG_ADDRESS_KEY_PHYSICAL;
    data[3] = 1; /* Look for Shelf FRU 1 */
    data[4] = PICMG_SITE_TYPE_SHELF_FRU_INFO;
    msg.data = data;
    msg.data_len = 5;

    return ipmi_send_command_addr(domain,
				  (ipmi_addr_t *) &si, sizeof(si),
				  &msg,
				  check_if_atca_cb, done, cb_data);
}

int
ipmi_oem_atca_init(void)
{
    int rv;

    rv = ipmi_register_domain_oem_check(check_if_atca, NULL);
    if (rv)
	return rv;

    return 0;
}

void
ipmi_oem_atca_shutdown(void)
{
    ipmi_deregister_domain_oem_check(check_if_atca, NULL);
}
