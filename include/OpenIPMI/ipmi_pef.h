/*
 * ipmi_pef.h
 *
 * OpenIPMI interface for dealing with platform event filters
 *
 * Author: Intel Corporation
 *         Jeff Zheng <Jeff.Zheng@intel.com>
 *
 * Mostly rewritten by: MontaVista Software, Inc.
 *                      Corey Minyard <minyard@mvista.com>
 *                      source@mvista.com
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

#ifndef _IPMI_PEF_H
#define _IPMI_PEF_H

#include <OpenIPMI/ipmi_types.h>

/* The abstract type for pef. */
typedef struct ipmi_pef_s ipmi_pef_t;


/* Generic callback used to tell when a PEF operation is done. */
typedef void (*ipmi_pef_done_cb)(ipmi_pef_t *pef,
				 int        err,
				 void       *cb_data);

/* Allocate a PEF.  The PEF will not be usable (it can only be
   destroyed) until the done callback is called. */
int ipmi_pef_alloc(ipmi_mc_t        *mc,
		   ipmi_pef_done_cb done,
		   void             *cb_data,
		   ipmi_pef_t       **new_pef);

/* Destroy a PEF. */
int ipmi_pef_destroy(ipmi_pef_t       *pef,
                     ipmi_pef_done_cb handler,
                     void             *cb_data);

/* Fetch a parameter value from the PEF.  The "set" and "block"
   parameters are the set selector and block selectors.  If those are
   not relevant for the given parm, then set them to zero. */
typedef void (*ipmi_pef_get_cb)(ipmi_pef_t    *pef,
				int           err,
				unsigned char *data,
				unsigned int  data_len,
				void          *cb_data);
int ipmi_pef_get_parm(ipmi_pef_t      *pef,
		      unsigned int    parm,
		      unsigned int    set,
		      unsigned int    block,
		      ipmi_pef_get_cb done,
		      void            *cb_data);

/* Set the parameter value in the PEF to the given data. */
int ipmi_pef_set_parm(ipmi_pef_t       *pef,
		      unsigned int     parm,
		      unsigned char    *data,
		      unsigned int     data_len,
		      ipmi_pef_done_cb done,
		      void             *cb_data);

/* Returns if the MC has a valid working PEF. */
int ipmi_pef_valid(ipmi_pef_t *pef);

/* Information fetched from the PEF capabilities. */
int ipmi_pef_supports_diagnostic_interrupt(ipmi_pef_t *pef);
int ipmi_pef_supports_oem_action(ipmi_pef_t *pef);
int ipmi_pef_supports_power_cycle(ipmi_pef_t *pef);
int ipmi_pef_supports_reset(ipmi_pef_t *pef);
int ipmi_pef_supports_power_down(ipmi_pef_t *pef);
int ipmi_pef_supports_alert(ipmi_pef_t *pef);

unsigned int ipmi_pef_major_version(ipmi_pef_t *pef);
unsigned int ipmi_pef_minor_version(ipmi_pef_t *pef);

unsigned int num_event_filter_table_entries(ipmi_pef_t *pef);

/* Entries in the PEF configuration. */

#define IPMI_PEFPARM_SET_IN_PROGRESS		0
#define IPMI_PEFPARM_CONTROL			1
#define IPMI_PEFPARM_ACTION_GLOBAL_CONTROL	2
#define IPMI_PEFPARM_STARTUP_DELAY		3
#define IPMI_PEFPARM_ALERT_STARTUP_DELAY	4
#define IPMI_PEFPARM_NUM_EVENT_FILTERS		5
#define IPMI_PEFPARM_EVENT_FILTER_TABLE		6
#define IPMI_PEFPARM_EVENT_FILTER_TABLE_DATA1	7
#define IPMI_PEFPARM_NUM_ALERT_POLICIES		8
#define IPMI_PEFPARM_ALERT_POLICY_TABLE		9
#define IPMI_PEFPARM_SYSTEM_GUID		10
#define IPMI_PEFPARM_NUM_ALERT_STRINGS		11
#define IPMI_PEFPARM_ALERT_STRING_KEY		12
#define IPMI_PEFPARM_ALERT_STRING		13


/* A full PEF configuration. */
typedef struct ipmi_pef_config_s ipmi_pef_config_t;

/* Get the full PEF configuration */
typedef void (*ipmi_pef_get_config_cb)(ipmi_pef_t        *pef,
				       int               err,
				       ipmi_pef_config_t *config,
				       void              *cb_data);
int ipmi_pef_get_config(ipmi_pef_t             *pef,
			ipmi_pef_get_config_cb done,
			void                   *cb_data);

/* Set the full PEF configuration.  Note that a copy is made of the
   configuration, so you are free to do whatever you like with it
   after this. */
int ipmi_pef_set_config(ipmi_pef_t        *pef,
			ipmi_pef_config_t *pefc,
			ipmi_pef_done_cb  done,
			void              *cb_data);

/* Free a PEF configuration. */
void ipmi_pef_free_config(ipmi_pef_config_t *config);

/*
 * Main configuration items for the PEF.
 */
unsigned int
ipmi_pefconfig_get_alert_startup_delay_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_alert_startup_delay_enabled(ipmi_pef_config_t *pefc,
						   unsigned int val);
unsigned int ipmi_pefconfig_get_startup_delay_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_startup_delay_enabled(ipmi_pef_config_t *pefc,
					     unsigned int val);
unsigned int ipmi_pefconfig_get_event_messages_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_event_messages_enabled(ipmi_pef_config_t *pefc,
					      unsigned int val);
unsigned int ipmi_pefconfig_get_pef_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_pef_enabled(ipmi_pef_config_t *pefc, unsigned int val);
unsigned int
ipmi_pefconfig_get_diagnostic_interrupt_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_diagnostic_interrupt_enabled(ipmi_pef_config_t *pefc,
						    unsigned int val);
unsigned int ipmi_pefconfig_get_oem_action_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_oem_action_enabled(ipmi_pef_config_t *pefc,
					  unsigned int val);
unsigned int ipmi_pefconfig_get_power_cycle_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_power_cycle_enabled(ipmi_pef_config_t *pefc,
					   unsigned int val);
unsigned int ipmi_pefconfig_get_reset_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_reset_enabled(ipmi_pef_config_t *pefc, unsigned int val);
unsigned int ipmi_pefconfig_get_power_down_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_power_down_enabled(ipmi_pef_config_t *pefc,
					  unsigned int val);
unsigned int ipmi_pefconfig_get_alert_enabled(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_set_alert_enabled(ipmi_pef_config_t *pefc, unsigned int val);
int ipmi_pefconfig_get_startup_delay(ipmi_pef_config_t *pefc,
				     unsigned int *val);
int ipmi_pefconfig_set_startup_delay(ipmi_pef_config_t *pefc,
				     unsigned int val);
int ipmi_pefconfig_get_alert_startup_delay(ipmi_pef_config_t *pefc,
					   unsigned int *val);
int ipmi_pefconfig_set_alert_startup_delay(ipmi_pef_config_t *pefc,
					   unsigned int val);

int ipmi_pefconfig_get_guid(ipmi_pef_config_t *pefc,
			    unsigned int      *enabled,
			    unsigned char     *data,
			    unsigned int      *data_len);
int ipmi_pefconfig_set_guid(ipmi_pef_config_t *pefc, unsigned int enabled,
			    unsigned char *data, unsigned int data_len);


/*
 * The following is for the event filter table entries.
 */
unsigned int ipmi_pefconfig_get_num_event_filters(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_get_enable_filter(ipmi_pef_config_t *pefc,
				     unsigned int      sel,
				     unsigned int      *val);
int ipmi_pefconfig_set_enable_filter(ipmi_pef_config_t *pefc,
				     unsigned int      sel,
				     unsigned int      val);

/* PEF Filter types */
#define IPMI_PEFPARM_EFT_FILTER_CONFIG_MANUFACTURE_CONFIG 2
#define IPMI_PEFPARM_EFT_FILTER_CONFIG_SOFTWARE_CONFIG 0

int ipmi_pefconfig_get_filter_type(ipmi_pef_config_t *pefc,
				   unsigned int      sel,
				   unsigned int      *val);
int ipmi_pefconfig_set_filter_type(ipmi_pef_config_t *pefc,
				   unsigned int      sel,
				   unsigned int      val);

int ipmi_pefconfig_get_diagnostic_interrupt(ipmi_pef_config_t *pefc,
					    unsigned int      sel,
					    unsigned int      *val);
int ipmi_pefconfig_set_diagnostic_interrupt(ipmi_pef_config_t *pefc,
					    unsigned int      sel,
					    unsigned int      val);

int ipmi_pefconfig_get_oem_action(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      *val);
int ipmi_pefconfig_set_oem_action(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      val);

int ipmi_pefconfig_get_power_cycle(ipmi_pef_config_t *pefc,
				   unsigned int      sel,
				   unsigned int      *val);
int ipmi_pefconfig_set_power_cycle(ipmi_pef_config_t *pefc,
				   unsigned int      sel,
				   unsigned int      val);

int ipmi_pefconfig_get_reset(ipmi_pef_config_t *pefc,
			     unsigned int      sel,
			     unsigned int      *val);
int ipmi_pefconfig_set_reset(ipmi_pef_config_t *pefc,
			     unsigned int      sel,
			     unsigned int      val);

int ipmi_pefconfig_get_power_down(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      *val);
int ipmi_pefconfig_set_power_down(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      val);

int ipmi_pefconfig_get_alert(ipmi_pef_config_t *pefc,
			     unsigned int      sel,
			     unsigned int      *val);
int ipmi_pefconfig_set_alert(ipmi_pef_config_t *pefc,
			     unsigned int      sel,
			     unsigned int      val);

int ipmi_pefconfig_get_alert_policy_number(ipmi_pef_config_t *pefc,
					   unsigned int      sel,
					   unsigned int      *val);
int ipmi_pefconfig_set_alert_policy_number(ipmi_pef_config_t *pefc,
					   unsigned int      sel,
					   unsigned int      val);

/* PEF event severities */
#define IPMI_PEFPARM_EVENT_SEVERITY_UNSPECIFIED 	0x00
#define IPMI_PEFPARM_EVENT_SEVERITY_MONITOR		0x01
#define IPMI_PEFPARM_EVENT_SEVERITY_INFORMATION		0x02
#define IPMI_PEFPARM_EVENT_SEVERITY_OK			0x04
#define IPMI_PEFPARM_EVENT_SEVERITY_NON_CRITICAL	0x08
#define IPMI_PEFPARM_EVENT_SEVERITY_CRITICAL		0x10
#define IPMI_PEFPARM_EVENT_SEVERITY_NON_RECOVERABLE	0x20
int ipmi_pefconfig_get_event_severity(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      *val);
int ipmi_pefconfig_set_event_severity(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      val);

int ipmi_pefconfig_get_generator_id_addr(ipmi_pef_config_t *pefc,
					 unsigned int      sel,
					 unsigned int      *val);
int ipmi_pefconfig_set_generator_id_addr(ipmi_pef_config_t *pefc,
					 unsigned int      sel,
					 unsigned int      val);

int ipmi_pefconfig_get_generator_id_channel_lun(ipmi_pef_config_t *pefc,
						unsigned int      sel,
						unsigned int      *val);
int ipmi_pefconfig_set_generator_id_channel_lun(ipmi_pef_config_t *pefc,
						unsigned int      sel,
						unsigned int      val);

int ipmi_pefconfig_get_sensor_type(ipmi_pef_config_t *pefc,
				   unsigned int      sel,
				   unsigned int      *val);
int ipmi_pefconfig_set_sensor_type(ipmi_pef_config_t *pefc,
				   unsigned int      sel,
				   unsigned int      val);

int ipmi_pefconfig_get_sensor_number(ipmi_pef_config_t *pefc,
				     unsigned int      sel,
				     unsigned int      *val);
int ipmi_pefconfig_set_sensor_number(ipmi_pef_config_t *pefc,
				     unsigned int      sel,
				     unsigned int      val);

int ipmi_pefconfig_get_event_trigger(ipmi_pef_config_t *pefc,
				     unsigned int      sel,
				     unsigned int      *val);
int ipmi_pefconfig_set_event_trigger(ipmi_pef_config_t *pefc,
				     unsigned int      sel,
				     unsigned int      val);

int ipmi_pefconfig_get_data1_offset_mask(ipmi_pef_config_t *pefc,
					 unsigned int      sel,
					 unsigned int      *val);
int ipmi_pefconfig_set_data1_offset_mask(ipmi_pef_config_t *pefc,
					 unsigned int      sel,
					 unsigned int      val);
int ipmi_pefconfig_get_data1_mask(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      *val);
int ipmi_pefconfig_set_data1_mask(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      val);
int ipmi_pefconfig_get_data1_compare1(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      *val);
int ipmi_pefconfig_set_data1_compare1(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      val);
int ipmi_pefconfig_get_data1_compare2(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      *val);
int ipmi_pefconfig_set_data1_compare2(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      val);

int ipmi_pefconfig_get_data2_mask(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      *val);
int ipmi_pefconfig_set_data2_mask(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      val);
int ipmi_pefconfig_get_data2_compare1(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      *val);
int ipmi_pefconfig_set_data2_compare1(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      val);
int ipmi_pefconfig_get_data2_compare2(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      *val);
int ipmi_pefconfig_set_data2_compare2(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      val);

int ipmi_pefconfig_get_data3_mask(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      *val);
int ipmi_pefconfig_set_data3_mask(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      val);
int ipmi_pefconfig_get_data3_compare1(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      *val);
int ipmi_pefconfig_set_data3_compare1(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      val);
int ipmi_pefconfig_get_data3_compare2(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      *val);
int ipmi_pefconfig_set_data3_compare2(ipmi_pef_config_t *pefc,
				      unsigned int      sel,
				      unsigned int      val);

/*
 * Values from the alert policy table.
 */
unsigned int ipmi_pefconfig_get_num_alert_policies(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_get_policy_num(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      *val);
int ipmi_pefconfig_set_policy_num(ipmi_pef_config_t *pefc,
				  unsigned int      sel,
				  unsigned int      val);
int ipmi_pefconfig_get_enabled(ipmi_pef_config_t *pefc,
			       unsigned int      sel,
			       unsigned int      *val);
int ipmi_pefconfig_set_enabled(ipmi_pef_config_t *pefc,
			       unsigned int      sel,
			       unsigned int      val);
int ipmi_pefconfig_get_policy(ipmi_pef_config_t *pefc,
			      unsigned int      sel,
			      unsigned int      *val);
int ipmi_pefconfig_set_policy(ipmi_pef_config_t *pefc,
			      unsigned int      sel,
			      unsigned int      val);
int ipmi_pefconfig_get_channel(ipmi_pef_config_t *pefc,
			       unsigned int      sel,
			       unsigned int      *val);
int ipmi_pefconfig_set_channel(ipmi_pef_config_t *pefc,
			       unsigned int      sel,
			       unsigned int      val);
int ipmi_pefconfig_get_destination_selector(ipmi_pef_config_t *pefc,
					    unsigned int      sel,
					    unsigned int      *val);
int ipmi_pefconfig_set_destination_selector(ipmi_pef_config_t *pefc,
					    unsigned int      sel,
					    unsigned int      val);
int ipmi_pefconfig_get_alert_string_event_specific(ipmi_pef_config_t *pefc,
						   unsigned int      sel,
						   unsigned int      *val);
int ipmi_pefconfig_set_alert_string_event_specific(ipmi_pef_config_t *pefc,
						   unsigned int      sel,
						   unsigned int      val);
int ipmi_pefconfig_get_alert_string_selector(ipmi_pef_config_t *pefc,
					     unsigned int      sel,
					     unsigned int      *val);
int ipmi_pefconfig_set_alert_string_selector(ipmi_pef_config_t *pefc,
					     unsigned int      sel,
					     unsigned int      val);

/*
 * Values from the alert string keys and alert strings
 */
unsigned int ipmi_pefconfig_get_num_alert_strings(ipmi_pef_config_t *pefc);
int ipmi_pefconfig_get_event_filter(ipmi_pef_config_t *pefc,
				    unsigned int      sel,
				    unsigned int      *val);
int ipmi_pefconfig_set_event_filter(ipmi_pef_config_t *pefc,
				    unsigned int      sel,
				    unsigned int      val);
int ipmi_pefconfig_get_alert_string_set(ipmi_pef_config_t *pefc,
					unsigned int      sel,
					unsigned int      *val);
int ipmi_pefconfig_set_alert_string_set(ipmi_pef_config_t *pefc,
					unsigned int      sel,
					unsigned int      val);
int ipmi_pefconfig_get_alert_string(ipmi_pef_config_t *pefc, unsigned int sel,
				    unsigned char *val, unsigned int len);
int ipmi_pefconfig_set_alert_string(ipmi_pef_config_t *pefc, unsigned int sel,
				    unsigned char *val);

#endif /* _IPMI_PEF_H */
