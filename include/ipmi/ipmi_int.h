/*
 * ipmi_int.h
 *
 * MontaVista IPMI interface, internal information.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
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

#ifndef _IPMI_INT_H
#define _IPMI_INT_H

/* Stuff used internally in the IPMI code, and possibly by OEM code. */

#include <ipmi/os_handler.h>
#include <ipmi/ipmi_mc.h>

/* There is a global read/write lock that protects the addition and
   removal of MCs and high-level information that doesn't change very
   much.  Grabbing the read lock keep anything from adding or removing
   MCs.  Grabbing the write lock give exclusive access to the MCs.  It's
   also used for protecting a few other things, too. */
void ipmi_read_lock(void);
void ipmi_read_unlock(void);
void ipmi_write_lock(void);
void ipmi_write_unlock(void);

/* This is a generic lock used by the IPMI code. */
typedef struct ipmi_lock_s ipmi_lock_t;

/* Create a lock, using the OS handlers for the given MC. */
int ipmi_create_lock(ipmi_mc_t *mc, ipmi_lock_t **lock);

/* Create a lock but us your own OS handlers. */
int ipmi_create_lock_os_hnd(os_handler_t *os_hnd, ipmi_lock_t **lock);

/* Destroy a lock. */
void ipmi_destroy_lock(ipmi_lock_t *lock);

/* Lock the lock.  Locks are recursive, so the same thread can claim
   the same lock multiple times, and must release it the same number
   of times. */
void ipmi_lock(ipmi_lock_t *lock);

/* Release the lock. */
void ipmi_unlock(ipmi_lock_t *lock);

/* The sensor code calls the MC code with this when it finds a new
   sensor.  If this returns 1, the sensor will NOT be added to the
   list of sensors in then entity.  This will call the OEM code if it
   has registered for this. */
int ipmi_bmc_oem_new_sensor(ipmi_mc_t     *mc,
			    ipmi_entity_t *ent,
			    ipmi_sensor_t *sensor,
			    void          *link);

/* This is called by the entity code when a new entity is created.
   Entity creation cannot be stopped.  This will call the OEM code if
   it has registered for this. */
void ipmi_bmc_oem_new_entity(ipmi_mc_t *bmc, ipmi_entity_t *ent);

#endif /* _IPMI_INT_H */
