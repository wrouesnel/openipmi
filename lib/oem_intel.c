/*
 * oem_intel.c
 *
 * OEM code to make Intel server systems work better.
 *
 * 08/19/04 ARCress - handle different bus ids for alarm panel.
 *
 *  (C) 2004 MontaVista Software, Inc.
 *  (C) 2004 Intel Corp.
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

#include <alloca.h>
#include <string.h>
#include <stdlib.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_oem.h>
#include <OpenIPMI/ipmi_sensor.h>
#include <OpenIPMI/ipmi_control.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_addr.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_domain.h>
#include <OpenIPMI/ipmi_event.h>
#include <OpenIPMI/ipmi_msgbits.h>

#define INTEL_MANUFACTURER_ID 0x000157
#define NSC_MANUFACTURER_ID 0x000322

static unsigned char busid = 0x03;   /*default to PRIVATE_BUS_ID;  */

static int get_alarm_control_number(int ipmb)
{
        return (ipmb >> 1);
}

static int
alarm_entity_sdr_add(ipmi_entity_t   *ent,
		     ipmi_sdr_info_t *sdrs,
		     void            *cb_data)
{
    /* Don't put the entities into an SDR */
    return 0;
}

typedef struct alarm_set_info_s
{
    ipmi_control_op_cb     handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
    int                    vals[1];
} alarm_set_info_t;

static void
alarm_set_cb(ipmi_control_t *control,
             int            err,
             ipmi_msg_t     *rsp,
             void           *cb_data)
{
    alarm_set_info_t *control_info = cb_data;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_intel.c: Received IPMI error: %x",
		 CONTROL_NAME(control), rsp->data[0]);
	if (control_info->handler)
	    control_info->handler(control,
				  IPMI_IPMI_ERR_VAL(rsp->data[0]),
				  control_info->cb_data);
	goto out;
    }

    if (control_info->handler)
	control_info->handler(control, 0, control_info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
alarm_set_start(ipmi_control_t *control, int err, void *cb_data)
{
    alarm_set_info_t *control_info = cb_data;
    ipmi_msg_t       msg;
    ipmi_mc_t	     *mc = ipmi_control_get_mc(control);
    int              rv;

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    if (ipmi_mc_manufacturer_id(mc) == NSC_MANUFACTURER_ID)  
	 busid = 0x24;  /* PERIPHERAL_BUS_ID */
    else busid = 0x03;  /* PRIVATE_BUS_ID */

    msg.netfn    = IPMI_APP_NETFN;
    msg.cmd      = IPMI_MASTER_READ_WRITE_CMD;
    msg.data     = alloca(4);
    msg.data_len = 4;
    msg.data[0]  = busid;
    msg.data[1]  = 0x40; /* ALARMS_PANEL_WRITE */
    msg.data[2]  = 1;
    msg.data[3]  = control_info->vals[0];

    rv = ipmi_control_send_command(control, mc, 0,
				   &msg, alarm_set_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->handler)
	    control_info->handler(control, rv, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
alarm_led_set(ipmi_control_t     *control,
	      int                *val,
	      ipmi_control_op_cb handler,
	      void               *cb_data)
{
    alarm_set_info_t  *control_info;
    int                rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    control_info->handler = handler;
    control_info->cb_data = cb_data;
    control_info->vals[0] = val[0];
    rv = ipmi_control_add_opq(control, alarm_set_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

typedef struct alarm_get_info_s
{
    ipmi_control_val_cb    handler;
    void                   *cb_data;
    ipmi_control_op_info_t sdata;
} alarm_get_info_t;

static void
alarm_get_cb(ipmi_control_t *control,
	     int            err,
	     ipmi_msg_t     *rsp,
	     void           *cb_data)
{
    alarm_get_info_t *control_info = cb_data;
    int              val[1];

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data[0] != 0) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_intel.c: Received IPMI error: %x",
		 CONTROL_NAME(control), rsp->data[0]);
	if (control_info->handler)
	    control_info->handler(control,
				  IPMI_IPMI_ERR_VAL(rsp->data[0]),
				  NULL, control_info->cb_data);
	goto out;
    }

    if (rsp->data_len < 2) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "%soem_intel.c: response too short: %d",
		 CONTROL_NAME(control), rsp->data_len);
	if (control_info->handler)
	    control_info->handler(control, EINVAL,
				  NULL, control_info->cb_data);
	goto out;
    }

    val[0] = rsp->data[1];
    if (control_info->handler)
	control_info->handler(control, 0,
			      val, control_info->cb_data);

 out:
    ipmi_control_opq_done(control);
    ipmi_mem_free(control_info);
}

static void
alarm_get_start(ipmi_control_t *control, int err, void *cb_data)
{
    alarm_get_info_t *control_info = cb_data;
    int              rv;
    ipmi_msg_t       msg;
    ipmi_mc_t	     *mc = ipmi_control_get_mc(control);

    if (err) {
	if (control_info->handler)
	    control_info->handler(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
	return;
    }

    if (ipmi_mc_manufacturer_id(mc) == NSC_MANUFACTURER_ID)  
	 busid = 0x24;  /* PERIPHERAL_BUS_ID */
    else busid = 0x03;  /* PRIVATE_BUS_ID */

    msg.netfn    = IPMI_APP_NETFN;
    msg.cmd      = IPMI_MASTER_READ_WRITE_CMD;
    msg.data     = alloca(3);
    msg.data_len = 3;
    msg.data[0]  = busid;
    msg.data[1]  = 0x41; /* ALARMS_PANEL_READ */
    msg.data[2]  = 1;

    rv = ipmi_control_send_command(control, mc, 0,
				   &msg, alarm_get_cb,
				   &(control_info->sdata), control_info);
    if (rv) {
	if (control_info->handler)
	    control_info->handler(control, err, 0, control_info->cb_data);
	ipmi_control_opq_done(control);
	ipmi_mem_free(control_info);
    }
}

static int
alarm_led_get(ipmi_control_t      *control,
	      ipmi_control_val_cb handler,
	      void                *cb_data)
{
    alarm_get_info_t *control_info;
    int              rv;

    control_info = ipmi_mem_alloc(sizeof(*control_info));
    if (!control_info)
	return ENOMEM;
    memset(control_info, 0, sizeof(*control_info));
    control_info->handler = handler;
    control_info->cb_data = cb_data;
    rv = ipmi_control_add_opq(control, alarm_get_start,
			     &(control_info->sdata), control_info);
    if (rv)
	ipmi_mem_free(control_info);
    return rv;
}

static void
add_alarm_handler(ipmi_mc_t *mc)
{
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_entity_info_t *ents = ipmi_domain_get_entities(domain);
    ipmi_entity_t      *ent;
    ipmi_control_t     *control;
    int                rv = 0;
    ipmi_control_cbs_t cbs;

    /* Add alarm panel entity */
    rv = ipmi_entity_add(ents, domain, 0, 0, 0,
                         IPMI_ENTITY_ID_FRONT_PANEL_BOARD, 1,
                         "Alarm Panel", IPMI_ASCII_STR, 11,
                         alarm_entity_sdr_add,
                         NULL, &ent);
    if (rv) {
            ipmi_log(IPMI_LOG_WARNING,
                     "%s oem_intel.c: could not add alarm panel entity"
                     "Could not add the MC entity: %x",
                     MC_NAME(mc), rv);
            goto out;
    }

    /* Allocate the alarm control. */
    rv = ipmi_control_alloc_nonstandard(&control);
    if (rv) {
            goto out;
    }

    ipmi_control_set_type(control, IPMI_CONTROL_ALARM);
    ipmi_control_set_ignore_if_no_entity(control, 0);
    ipmi_control_set_id(control, "alarm", IPMI_ASCII_STR, 5);

    ipmi_control_set_settable(control, 1);
    ipmi_control_set_readable(control, 1);

    memset(&cbs, 0, sizeof(cbs));
    cbs.set_val = alarm_led_set;
    cbs.get_val = alarm_led_get;

    ipmi_control_set_callbacks(control, &cbs);
    ipmi_control_set_num_elements(control, 1);

    /* Add it to the MC and entity.  We presume this comes from the
       "main" SDR, so set the source_mc to NULL. */
    rv = ipmi_control_add_nonstandard(mc, NULL, control,
                                      get_alarm_control_number(0x40),
                                      ent, NULL, NULL);

    if (rv) {
            ipmi_log(IPMI_LOG_WARNING,
                     "%soem_intel.c: "
                     "Could not add the alarm control: %x",
                     MC_NAME(mc), rv);
            ipmi_control_destroy(control);
            goto out;
    }

out:
    return;
}

static int
tsrlt2_handler(ipmi_mc_t *mc,
	       void      *cb_data)
{
    ipmi_domain_t *domain = ipmi_mc_get_domain(mc);
    unsigned int  channel = ipmi_mc_get_channel(mc);
    unsigned int  addr    = ipmi_mc_get_address(mc);

    if ((channel == IPMI_BMC_CHANNEL) && (addr == IPMI_BMC_CHANNEL)) {
	/* It's the SI MC, which we detect at startup.  Set up the MCs
	   for the domain to scan. */
	/* We scan 0x20 and 0x28 */
	ipmi_domain_add_ipmb_ignore_range(domain, 0x00, 0x1f);
	ipmi_domain_add_ipmb_ignore_range(domain, 0x21, 0x27);
	ipmi_domain_add_ipmb_ignore_range(domain, 0x29, 0xff);
    }

    return 0;
}

static int
tig_handler(ipmi_mc_t *mc,
	    void      *cb_data)
{
    ipmi_domain_t *domain = ipmi_mc_get_domain(mc);
    unsigned int  channel = ipmi_mc_get_channel(mc);
    unsigned int  addr    = ipmi_mc_get_address(mc);
    
    if ((channel == IPMI_BMC_CHANNEL) && (addr == IPMI_BMC_CHANNEL)) {
	/* It's the SI MC, which we detect at startup.  Set up the MCs
	   for the domain to scan. */
	/* We scan 0x20, 0x28, and 0xc0 */
	ipmi_domain_add_ipmb_ignore_range(domain, 0x00, 0x1f);
	ipmi_domain_add_ipmb_ignore_range(domain, 0x21, 0x27);
	ipmi_domain_add_ipmb_ignore_range(domain, 0x29, 0xbf);
	ipmi_domain_add_ipmb_ignore_range(domain, 0xc1, 0xff);
	add_alarm_handler(mc);
    }

    return 0;
}

int
ipmi_oem_intel_init(void)
{
    int rv;

    rv = ipmi_register_oem_handler(INTEL_MANUFACTURER_ID,
				   0x000c,
				   tsrlt2_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    rv = ipmi_register_oem_handler(INTEL_MANUFACTURER_ID,
				   0x001b,
				   tig_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    rv = ipmi_register_oem_handler(INTEL_MANUFACTURER_ID,
				   0x0103,
				   tig_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    rv = ipmi_register_oem_handler(NSC_MANUFACTURER_ID,
				   0x4311,
				   tig_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    return 0;
}

void
ipmi_oem_intel_shutdown(void)
{
    ipmi_deregister_oem_handler(INTEL_MANUFACTURER_ID, 0x000c);
    ipmi_deregister_oem_handler(INTEL_MANUFACTURER_ID, 0x001b);
    ipmi_deregister_oem_handler(INTEL_MANUFACTURER_ID, 0x0103);
    ipmi_deregister_oem_handler(NSC_MANUFACTURER_ID, 0x4311);
}
