/*
 * ipmi_fru.h
 *
 * IPMI interface for FRUs
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

#ifndef _IPMI_FRU_H
#define _IPMI_FRU_H
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_types.h>

/* chassis types */
#define IPMI_FRU_CT_OTHER                  1
#define IPMI_FRU_CT_UNKNOWN                2
#define IPMI_FRU_CT_DESKTOP                3
#define IPMI_FRU_CT_LOW_PROFILE_DESKTOP    4
#define IPMI_FRU_CT_PIZZA_BOX              5
#define IPMI_FRU_CT_MINI_TOWER             6
#define IPMI_FRU_CT_TOWER                  7
#define IPMI_FRU_CT_PORTABLE               8
#define IPMI_FRU_CT_LAPTOP                 9
#define IPMI_FRU_CT_NOTEBOOK              10
#define IPMI_FRU_CT_HANDHELD              11
#define IPMI_FRU_CT_DOCKING_STATION       12
#define IPMI_FRU_CT_ALL_IN_ONE            13
#define IPMI_FRU_CT_SUB_NOTEBOOK          14
#define IPMI_FRU_CT_SPACE_SAVING          15
#define IPMI_FRU_CT_LUNCH_BOX             16
#define IPMI_FRU_CT_MAIN_SERVER_CHASSIS   17
#define IPMI_FRU_CT_EXPANSION_CHASSIS     18
#define IPMI_FRU_CT_SUB_CHASSIS           19
#define IPMI_FRU_CT_BUS_EXPANSION_CHASSIS 20
#define IPMI_FRU_CT_PERIPERAL_CHASSIS     21
#define IPMI_FRU_CT_RAID_CHASSIS          22
#define IPMI_FRU_CT_RACK_MOUNT_CHASSIS    23


typedef void (*ipmi_fru_fetched_cb)(ipmi_fru_t *fru, int err, void *cb_data);
int ipmi_fru_alloc(ipmi_domain_t *domain,
		   unsigned char is_logical,
		   unsigned char device_address,
		   unsigned char device_id,
		   unsigned char lun,
		   unsigned char private_bus,
		   unsigned char channel,
		   ipmi_fru_fetched_cb fetched_handler,
		   void                *fetched_cb_data,
		   ipmi_fru_t    **new_fru);

/* Destroy an FRU.  Note that if the FRU is currently fetching SDRs,
   the destroy cannot complete immediatly, it will be marked for
   destruction later.  You can supply a callback that, if not NULL,
   will be called when the sdr is destroyed. */
typedef void (*ipmi_fru_destroyed_cb)(ipmi_fru_t *fru, void *cb_data);
int ipmi_fru_destroy(ipmi_fru_t            *fru,
		     ipmi_fru_destroyed_cb handler,
		     void                  *cb_data);



#endif /* _IPMI_FRU_H */
