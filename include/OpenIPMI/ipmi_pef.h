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

typedef struct ipmi_pef_config_s ipmi_pef_config_t;

typedef void (*ipmi_pef_get_config_cb)(ipmi_pef_t        *pef,
				       int               err,
				       ipmi_pef_config_t *config,
				       void              *cb_data);
int ipmi_pef_get_config(ipmi_pef_t             *pef,
			ipmi_pef_get_config_cb done,
			void                   *cb_data);
int ipmi_pef_set_config(ipmi_pef_t        *pef,
			ipmi_pef_config_t *pefc,
			ipmi_pef_done_cb  done,
			void              *cb_data);
void ipmi_pef_free_config(ipmi_pef_config_t *config);
					 
/* PEF Filter types */
#define IPMI_PEFPARM_EFT_FILTER_CONFIG_MANUFACTURE_CONFIG 2
#define IPMI_PEFPARM_EFT_FILTER_CONFIG_SOFTWARE_CONFIG 0

/* PEF event severities */
#define IPMI_PEFPARM_EVENT_SEVERITY_UNSPECIFIED 	0x00
#define IPMI_PEFPARM_EVENT_SEVERITY_MONITOR		0x01
#define IPMI_PEFPARM_EVENT_SEVERITY_INFORMATION		0x02
#define IPMI_PEFPARM_EVENT_SEVERITY_OK			0x04
#define IPMI_PEFPARM_EVENT_SEVERITY_NON_CRITICAL	0x08
#define IPMI_PEFPARM_EVENT_SEVERITY_CRITICAL		0x10
#define IPMI_PEFPARM_EVENT_SEVERITY_NON_RECOVERABLE	0x20


#endif /* _IPMI_PEF_H */
