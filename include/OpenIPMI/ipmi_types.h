/*
 * ipmi_types.h
 *
 * MontaVista IPMI interface general types.
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

#ifndef _IPMI_TYPES_H
#define _IPMI_TYPES_H
/*
 * These are the main types the user has to deal with.
 */

/*
 * This represents an intelligent entity on the IPMI bus, called a
 * "Management Controller" (MC).  The first one reported for a
 * registered device is the "SMI" one.  You can query the SMI MC for
 * the satellite devices.
 */
typedef struct ipmi_mc_s ipmi_mc_t;
typedef struct ipmi_mc_id_s ipmi_mc_id_t;

/*
 * An entity is a physical device that can be monitored or controlled.
 */
typedef struct ipmi_entity_s ipmi_entity_t;
typedef struct ipmi_entity_id_s ipmi_entity_id_t;

/*
 * A sensor is something connected to an entity that can monitor or control
 * the entity.
 */
typedef struct ipmi_sensor_s ipmi_sensor_t;
typedef struct ipmi_sensor_id_s ipmi_sensor_id_t;

/*
 * An indicator is an output device, such as a light, relay, or display.
 */
typedef struct ipmi_control_s ipmi_control_t;
typedef struct ipmi_control_id_s ipmi_control_id_t;

#ifndef __LINUX_IPMI_H /* Don't include this is we are including the kernel */

#define IPMI_MAX_MSG_LENGTH	80

/* A raw IPMI message without any addressing.  This covers both
   commands and responses.  The completion code is always the first
   byte of data in the response (as the spec shows the messages laid
   out). */
typedef struct ipmi_msg
{
    unsigned char  netfn;
    unsigned char  cmd;
    unsigned short data_len;
    unsigned char  *data;
} ipmi_msg_t;

#else

/* Generate a type for the kernel version of this. */
typedef struct ipmi_msg ipmi_msg_t;

#endif

/* Pay no attention to the contents of these structures... */
struct ipmi_mc_id_s
{
    ipmi_mc_t    *bmc;
    unsigned int mc_num  : 8;
    unsigned int channel : 4;
    long         seq;
};

struct ipmi_entity_id_s
{
    ipmi_mc_id_t bmc_id;
    unsigned int entity_id       : 8;
    unsigned int entity_instance : 4;
    unsigned int channel         : 8;
    unsigned int address         : 8;
    long         seq;
};

struct ipmi_sensor_id_s
{
    ipmi_mc_id_t mc_id;
    unsigned int lun        : 3;
    unsigned int sensor_num : 8;
};

struct ipmi_control_id_s
{
    ipmi_mc_id_t mc_id;
    unsigned int lun         : 3;
    unsigned int control_num : 8;
};

/* Maximum amount of data allowed in a SEL. */
#define IPMI_MAX_SEL_DATA 13
/* An entry from the system event log. */
typedef struct ipmi_event_s
{
    ipmi_mc_id_t  mc_id; /* The MC that this event came from. */

    unsigned int  record_id;
    unsigned int  type;
    unsigned char data[IPMI_MAX_SEL_DATA];
} ipmi_event_t;

/* This represents a low-level connection. */
typedef struct ipmi_con_s ipmi_con_t;

#endif /* _IPMI_TYPES_H */
