/*
 * priv_table.h
 *
 * MontaVista IPMI interface, table and associated code for figuring
 * out priviledge levels for messages.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2003,2004,2005 MontaVista Software Inc.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * Lesser General Public License (GPL) Version 2 or the modified BSD
 * license below.  The following disclamer applies to both licenses:
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
 * GNU Lesser General Public Licence
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Modified BSD Licence
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *   3. The name of the author may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 */

#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_msgbits.h>

#define PRIV_ENTRY(c,u,o,a) ((c) | ((u)<<4) | ((o)<<8) | ((a)<<12))

typedef unsigned short priv_val;

#define n 0 /* No priviledge (blank entry) */
#define s 1 /* System interface only. */
#define p 2 /* No authentication required. */
#define X 3 /* Permitted */
#define b 4 /* bmc-only */
#define h 5 /* special send-message handling is needed. */
#define i 6 /* Special set system boot options handling. */
#define b2 7 /* bmc-only, can be sent to a serial channel when serial
		port sharing is used and actvating the SOL payload
		causes the serial session to be terminated. */

/* An entry marked with a comment at the beginning has special
   handling. */

/* Chassis netfn (0x00) */
static priv_val chassis_privs[] =
{
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_CHASSIS_CAPABILITIES_CMD		0x00 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_CHASSIS_STATUS_CMD			0x01 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_CHASSIS_CONTROL_CMD			0x02 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_CHASSIS_RESET_CMD			0x03 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_CHASSIS_IDENTIFY_CMD			0x04 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_CHASSIS_CAPABILITIES_CMD		0x05 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_POWER_RESTORE_POLICY_CMD		0x06 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SYSTEM_RESTART_CAUSE_CMD		0x07 */
/**/PRIV_ENTRY(n,n,X,X), /* IPMI_SET_SYSTEM_BOOT_OPTIONS_CMD		0x08 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_GET_SYSTEM_BOOT_OPTIONS_CMD		0x09 */
    PRIV_ENTRY(n,n,n,X), /*						0x0a */
    PRIV_ENTRY(n,n,n,X), /*						0x0b */
    PRIV_ENTRY(n,n,n,X), /*						0x0c */
    PRIV_ENTRY(n,n,n,X), /*						0x0d */
    PRIV_ENTRY(n,n,n,X), /*						0x0e */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_POH_COUNTER_CMD			0x0f */
};

/* Bridge netfn (0x02) */
static priv_val bridge_privs[] =
{
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_BRIDGE_STATE_CMD			0x00 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_BRIDGE_STATE_CMD			0x01 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_ICMB_ADDRESS_CMD			0x02 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_ICMB_ADDRESS_CMD			0x03 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_BRIDGE_PROXY_ADDRESS_CMD		0x04 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_BRIDGE_STATISTICS_CMD		0x05 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_ICMB_CAPABILITIES_CMD		0x06 */
    PRIV_ENTRY(n,n,n,X), /*						0x07 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_CLEAR_BRIDGE_STATISTICS_CMD		0x08 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_BRIDGE_PROXY_ADDRESS_CMD		0x09 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_ICMB_CONNECTOR_INFO_CMD		0x0a */
    PRIV_ENTRY(n,X,X,X), /* IPMI_SET_ICMB_CONNECTOR_INFO_CMD		0x0b */
    PRIV_ENTRY(n,X,X,X), /* IPMI_SEND_ICMB_CONNECTION_ID_CMD		0x0c */
    PRIV_ENTRY(n,n,n,X), /*						0x0d */
    PRIV_ENTRY(n,n,n,X), /*						0x0e */
    PRIV_ENTRY(n,n,n,X), /*						0x0f */
    PRIV_ENTRY(n,n,X,X), /* IPMI_PREPARE_FOR_DISCOVERY_CMD		0x10 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_ADDRESSES_CMD			0x11 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_DISCOVERED_CMD			0x12 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_CHASSIS_DEVICE_ID_CMD		0x13 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_CHASSIS_DEVICE_ID_CMD		0x14 */
    PRIV_ENTRY(n,n,n,X), /*						0x15 */
    PRIV_ENTRY(n,n,n,X), /*						0x16 */
    PRIV_ENTRY(n,n,n,X), /*						0x17 */
    PRIV_ENTRY(n,n,n,X), /*						0x18 */
    PRIV_ENTRY(n,n,n,X), /*						0x19 */
    PRIV_ENTRY(n,n,n,X), /*						0x1a */
    PRIV_ENTRY(n,n,n,X), /*						0x1b */
    PRIV_ENTRY(n,n,n,X), /*						0x1c */
    PRIV_ENTRY(n,n,n,X), /*						0x1d */
    PRIV_ENTRY(n,n,n,X), /*						0x1e */
    PRIV_ENTRY(n,n,n,X), /*						0x1f */
    PRIV_ENTRY(n,n,X,X), /* IPMI_BRIDGE_REQUEST_CMD			0x20 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_BRIDGE_MESSAGE_CMD			0x21 */
    PRIV_ENTRY(n,n,n,X), /*						0x22 */
    PRIV_ENTRY(n,n,n,X), /*						0x23 */
    PRIV_ENTRY(n,n,n,X), /*						0x24 */
    PRIV_ENTRY(n,n,n,X), /*						0x25 */
    PRIV_ENTRY(n,n,n,X), /*						0x26 */
    PRIV_ENTRY(n,n,n,X), /*						0x27 */
    PRIV_ENTRY(n,n,n,X), /*						0x28 */
    PRIV_ENTRY(n,n,n,X), /*						0x29 */
    PRIV_ENTRY(n,n,n,X), /*						0x2a */
    PRIV_ENTRY(n,n,n,X), /*						0x2b */
    PRIV_ENTRY(n,n,n,X), /*						0x2c */
    PRIV_ENTRY(n,n,n,X), /*						0x2d */
    PRIV_ENTRY(n,n,n,X), /*						0x2e */
    PRIV_ENTRY(n,n,n,X), /*						0x2f */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_EVENT_COUNT_CMD			0x30 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_EVENT_DESTINATION_CMD		0x31 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_EVENT_RECEPTION_STATE_CMD		0x32 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SEND_ICMB_EVENT_MESSAGE_CMD		0x33 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_EVENT_DESTIATION_CMD		0x34 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_EVENT_RECEPTION_STATE_CMD		0x35 */
#if 0
/* Handled as administrator by virtue of not being there. */
/**/PRIV_ENTRY(n,n,n,X), /* IPMI_ERROR_REPORT_CMD			0xff */
#endif
};

/* Sensor/Event netfn (0x04) */
static priv_val sensor_privs[] =
{
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_EVENT_RECEIVER_CMD			0x00 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_EVENT_RECEIVER_CMD			0x01 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_PLATFORM_EVENT_CMD			0x02 */
    PRIV_ENTRY(n,n,n,X), /*						0x03 */
    PRIV_ENTRY(n,n,n,X), /*						0x04 */
    PRIV_ENTRY(n,n,n,X), /*						0x05 */
    PRIV_ENTRY(n,n,n,X), /*						0x06 */
    PRIV_ENTRY(n,n,n,X), /*						0x07 */
    PRIV_ENTRY(n,n,n,X), /*						0x08 */
    PRIV_ENTRY(n,n,n,X), /*						0x09 */
    PRIV_ENTRY(n,n,n,X), /*						0x0a */
    PRIV_ENTRY(n,n,n,X), /*						0x0b */
    PRIV_ENTRY(n,n,n,X), /*						0x0c */
    PRIV_ENTRY(n,n,n,X), /*						0x0d */
    PRIV_ENTRY(n,n,n,X), /*						0x0e */
    PRIV_ENTRY(n,n,n,X), /*						0x0f */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_PEF_CAPABILITIES_CMD		0x10 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_ARM_PEF_POSTPONE_TIMER_CMD		0x11 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_PEF_CONFIG_PARMS_CMD		0x12 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_GET_PEF_CONFIG_PARMS_CMD		0x13 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_LAST_PROCESSED_EVENT_ID_CMD	0x14 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_GET_LAST_PROCESSED_EVENT_ID_CMD	0x15 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_ALERT_IMMEDIATE_CMD			0x16 */
    PRIV_ENTRY(p,p,p,p), /* IPMI_PET_ACKNOWLEDGE_CMD			0x17 */
    PRIV_ENTRY(n,n,n,X), /*						0x18 */
    PRIV_ENTRY(n,n,n,X), /*						0x19 */
    PRIV_ENTRY(n,n,n,X), /*						0x1a */
    PRIV_ENTRY(n,n,n,X), /*						0x1b */
    PRIV_ENTRY(n,n,n,X), /*						0x1c */
    PRIV_ENTRY(n,n,n,X), /*						0x1d */
    PRIV_ENTRY(n,n,n,X), /*						0x1e */
    PRIV_ENTRY(n,n,n,X), /*						0x1f */
    /* Note, the following are "I I I I" in the table, but I think
       that's wrong. */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_DEVICE_SDR_INFO_CMD		0x20 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_DEVICE_SDR_CMD			0x21 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_RESERVE_DEVICE_SDR_REPOSITORY_CMD	0x22 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SENSOR_READING_FACTORS_CMD		0x23 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_SENSOR_HYSTERESIS_CMD		0x24 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SENSOR_HYSTERESIS_CMD		0x25 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_SENSOR_THRESHOLD_CMD		0x26 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SENSOR_THRESHOLD_CMD		0x27 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_SENSOR_EVENT_ENABLE_CMD		0x28 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SENSOR_EVENT_ENABLE_CMD		0x29 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_REARM_SENSOR_EVENTS_CMD		0x2a */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SENSOR_EVENT_STATUS_CMD		0x2b */
    PRIV_ENTRY(n,n,n,X), /*						0x2c */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SENSOR_READING_CMD			0x2d */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_SENSOR_TYPE_CMD			0x2e */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SENSOR_TYPE_CMD			0x2f */
};

/* App netfn (0x06) */
static priv_val app_privs[] =
{
    PRIV_ENTRY(n,n,n,X), /*						0x00 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_DEVICE_ID_CMD			0x01 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_COLD_RESET_CMD				0x02 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_WARM_RESET_CMD				0x03 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SELF_TEST_RESULTS_CMD		0x04 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_MANUFACTURING_TEST_ON_CMD		0x05 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_ACPI_POWER_STATE_CMD		0x06 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_ACPI_POWER_STATE_CMD		0x07 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_DEVICE_GUID_CMD			0x08 */
    PRIV_ENTRY(n,n,n,X), /*						0x09 */
    PRIV_ENTRY(n,n,n,X), /*						0x0a */
    PRIV_ENTRY(n,n,n,X), /*						0x0b */
    PRIV_ENTRY(n,n,n,X), /*						0x0c */
    PRIV_ENTRY(n,n,n,X), /*						0x0d */
    PRIV_ENTRY(n,n,n,X), /*						0x0e */
    PRIV_ENTRY(n,n,n,X), /*						0x0f */
    PRIV_ENTRY(n,n,n,X), /*						0x10 */
    PRIV_ENTRY(n,n,n,X), /*						0x11 */
    PRIV_ENTRY(n,n,n,X), /*						0x12 */
    PRIV_ENTRY(n,n,n,X), /*						0x13 */
    PRIV_ENTRY(n,n,n,X), /*						0x14 */
    PRIV_ENTRY(n,n,n,X), /*						0x15 */
    PRIV_ENTRY(n,n,n,X), /*						0x16 */
    PRIV_ENTRY(n,n,n,X), /*						0x17 */
    PRIV_ENTRY(n,n,n,X), /*						0x18 */
    PRIV_ENTRY(n,n,n,X), /*						0x19 */
    PRIV_ENTRY(n,n,n,X), /*						0x1a */
    PRIV_ENTRY(n,n,n,X), /*						0x1b */
    PRIV_ENTRY(n,n,n,X), /*						0x1c */
    PRIV_ENTRY(n,n,n,X), /*						0x1d */
    PRIV_ENTRY(n,n,n,X), /*						0x1e */
    PRIV_ENTRY(n,n,n,X), /*						0x1f */
    PRIV_ENTRY(n,n,n,X), /*						0x20 */
    PRIV_ENTRY(n,n,n,X), /*						0x21 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_RESET_WATCHDOG_TIMER_CMD		0x22 */
    PRIV_ENTRY(n,n,n,X), /*						0x23 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_WATCHDOG_TIMER_CMD			0x24 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_WATCHDOG_TIMER_CMD			0x25 */
    PRIV_ENTRY(n,n,n,X), /*						0x26 */
    PRIV_ENTRY(n,n,n,X), /*						0x27 */
    PRIV_ENTRY(n,n,n,X), /*						0x28 */
    PRIV_ENTRY(n,n,n,X), /*						0x29 */
    PRIV_ENTRY(n,n,n,X), /*						0x2a */
    PRIV_ENTRY(n,n,n,X), /*						0x2b */
    PRIV_ENTRY(n,n,n,X), /*						0x2c */
    PRIV_ENTRY(n,n,n,X), /*						0x2d */
    PRIV_ENTRY(s,s,s,s), /* IPMI_SET_BMC_GLOBAL_ENABLES_CMD		0x2e */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_BMC_GLOBAL_ENABLES_CMD		0x2f */
    PRIV_ENTRY(s,s,s,s), /* IPMI_CLEAR_MSG_FLAGS_CMD			0x30 */
    PRIV_ENTRY(s,s,s,s), /* IPMI_GET_MSG_FLAGS_CMD			0x31 */
    PRIV_ENTRY(s,s,s,s), /* IPMI_ENABLE_MESSAGE_CHANNEL_RCV_CMD		0x32 */
    PRIV_ENTRY(s,s,s,s), /* IPMI_GET_MSG_CMD				0x33 */
/**/PRIV_ENTRY(n,h,X,X), /* IPMI_SEND_MSG_CMD				0x34 */
    PRIV_ENTRY(s,s,s,s), /* IPMI_READ_EVENT_MSG_BUFFER_CMD		0x35 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_BT_INTERFACE_CAPABILITIES_CMD	0x36 */
    PRIV_ENTRY(p,p,p,p), /* IPMI_GET_SYSTEM_GUID_CMD			0x37 */
    PRIV_ENTRY(p,p,p,p), /* IPMI_GET_CHANNEL_AUTH_CAPABILITIES_CMD	0x38 */
    PRIV_ENTRY(p,p,p,p), /* IPMI_GET_SESSION_CHALLENGE_CMD		0x39 */
    PRIV_ENTRY(p,p,p,p), /* IPMI_ACTIVATE_SESSION_CMD			0x3a */
    PRIV_ENTRY(n,X,X,X), /* IPMI_SET_SESSION_PRIVILEGE_CMD		0x3b */
    PRIV_ENTRY(X,X,X,X), /* IPMI_CLOSE_SESSION_CMD			0x3c */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SESSION_INFO_CMD			0x3d */
    PRIV_ENTRY(n,n,n,X), /*						0x3e */
    PRIV_ENTRY(n,n,X,X), /* IPMI_GET_AUTHCODE_CMD			0x3f */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_CHANNEL_ACCESS_CMD			0x40 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_CHANNEL_ACCESS_CMD			0x41 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_CHANNEL_INFO_CMD			0x42 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_USER_ACCESS_CMD			0x43 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_GET_USER_ACCESS_CMD			0x44 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_USER_NAME_CMD			0x45 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_GET_USER_NAME_CMD			0x46 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_USER_PASSWORD_CMD			0x47 */
    PRIV_ENTRY(X,X,X,X), /* IPMI_ACTIVATE_PAYLOAD_CMD			0x48 */
    PRIV_ENTRY(X,X,X,X), /* IPMI_DEACTIVATE_PAYLOAD_CMD			0x49 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_PAYLOAD_ACTIVATION_STATUS_CMD	0x4a */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_PAYLOAD_INSTANCE_INFO_CMD		0x4b */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_USER_PAYLOAD_ACCESS_CMD		0x4c */
    PRIV_ENTRY(n,n,X,X), /* IPMI_GET_USER_PAYLOAD_ACCESS_CMD		0x4d */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_CHANNEL_PAYLOAD_SUPPORT_CMD	0x4e */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_CHANNEL_PAYLOAD_VERSION_CMD	0x4f */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_CHANNEL_OEM_PAYLOAD_INFO_CMD	0x50 */
    PRIV_ENTRY(n,n,n,X), /*						0x51 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_MASTER_READ_WRITE_CMD			0x52 */
    PRIV_ENTRY(n,n,n,X), /*						0x53 */
    PRIV_ENTRY(p,p,p,p), /* IPMI_GET_CHANNEL_CIPHER_SUITES_CMD		0x54 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_SUSPEND_RESUME_PAYLOAD_ENCRYPTION_CMD	0x55 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_CHANNEL_SECURITY_KEY_CMD		0x56 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SYSTEM_INTERFACE_CAPABILITIES_CMD	0x57 */
};

/* Firmware netfn (0x08) */
static priv_val firmware_privs[] =
{
    PRIV_ENTRY(n,n,n,X), /*						0x00 */
};

/* Storage netfn (0x0a) */
static priv_val storage_privs[] =
{
    PRIV_ENTRY(n,n,n,X), /*						0x00 */
    PRIV_ENTRY(n,n,n,X), /*						0x01 */
    PRIV_ENTRY(n,n,n,X), /*						0x02 */
    PRIV_ENTRY(n,n,n,X), /*						0x03 */
    PRIV_ENTRY(n,n,n,X), /*						0x04 */
    PRIV_ENTRY(n,n,n,X), /*						0x05 */
    PRIV_ENTRY(n,n,n,X), /*						0x06 */
    PRIV_ENTRY(n,n,n,X), /*						0x07 */
    PRIV_ENTRY(n,n,n,X), /*						0x08 */
    PRIV_ENTRY(n,n,n,X), /*						0x09 */
    PRIV_ENTRY(n,n,n,X), /*						0x0a */
    PRIV_ENTRY(n,n,n,X), /*						0x0b */
    PRIV_ENTRY(n,n,n,X), /*						0x0c */
    PRIV_ENTRY(n,n,n,X), /*						0x0d */
    PRIV_ENTRY(n,n,n,X), /*						0x0e */
    PRIV_ENTRY(n,n,n,X), /*						0x0f */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_FRU_INVENTORY_AREA_INFO_CMD	0x10 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_READ_FRU_DATA_CMD			0x11 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_WRITE_FRU_DATA_CMD			0x12 */
    PRIV_ENTRY(n,n,n,X), /*						0x13 */
    PRIV_ENTRY(n,n,n,X), /*						0x14 */
    PRIV_ENTRY(n,n,n,X), /*						0x15 */
    PRIV_ENTRY(n,n,n,X), /*						0x16 */
    PRIV_ENTRY(n,n,n,X), /*						0x17 */
    PRIV_ENTRY(n,n,n,X), /*						0x18 */
    PRIV_ENTRY(n,n,n,X), /*						0x19 */
    PRIV_ENTRY(n,n,n,X), /*						0x1a */
    PRIV_ENTRY(n,n,n,X), /*						0x1b */
    PRIV_ENTRY(n,n,n,X), /*						0x1c */
    PRIV_ENTRY(n,n,n,X), /*						0x1d */
    PRIV_ENTRY(n,n,n,X), /*						0x1e */
    PRIV_ENTRY(n,n,n,X), /*						0x1f */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SDR_REPOSITORY_INFO_CMD		0x20 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SDR_REPOSITORY_ALLOC_INFO_CMD	0x21 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_RESERVE_SDR_REPOSITORY_CMD		0x22 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SDR_CMD				0x23 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_ADD_SDR_CMD				0x24 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_PARTIAL_ADD_SDR_CMD			0x25 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_DELETE_SDR_CMD				0x26 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_CLEAR_SDR_REPOSITORY_CMD		0x27 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SDR_REPOSITORY_TIME_CMD		0x28 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_SDR_REPOSITORY_TIME_CMD		0x29 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_ENTER_SDR_REPOSITORY_UPDATE_CMD	0x2a */
    PRIV_ENTRY(n,n,X,X), /* IPMI_EXIT_SDR_REPOSITORY_UPDATE_CMD		0x2b */
    PRIV_ENTRY(n,n,X,X), /* IPMI_RUN_INITIALIZATION_AGENT_CMD		0x2c */
    PRIV_ENTRY(n,n,n,X), /*						0x2d */
    PRIV_ENTRY(n,n,n,X), /*						0x2e */
    PRIV_ENTRY(n,n,n,X), /*						0x2f */
    PRIV_ENTRY(n,n,n,X), /*						0x30 */
    PRIV_ENTRY(n,n,n,X), /*						0x31 */
    PRIV_ENTRY(n,n,n,X), /*						0x32 */
    PRIV_ENTRY(n,n,n,X), /*						0x33 */
    PRIV_ENTRY(n,n,n,X), /*						0x34 */
    PRIV_ENTRY(n,n,n,X), /*						0x35 */
    PRIV_ENTRY(n,n,n,X), /*						0x36 */
    PRIV_ENTRY(n,n,n,X), /*						0x37 */
    PRIV_ENTRY(n,n,n,X), /*						0x38 */
    PRIV_ENTRY(n,n,n,X), /*						0x39 */
    PRIV_ENTRY(n,n,n,X), /*						0x3a */
    PRIV_ENTRY(n,n,n,X), /*						0x4b */
    PRIV_ENTRY(n,n,n,X), /*						0x3c */
    PRIV_ENTRY(n,n,n,X), /*						0x3d */
    PRIV_ENTRY(n,n,n,X), /*						0x3e */
    PRIV_ENTRY(n,n,n,X), /*						0x3f */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SEL_INFO_CMD			0x40 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SEL_ALLOCATION_INFO_CMD		0x41 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_RESERVE_SEL_CMD			0x42 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SEL_ENTRY_CMD			0x43 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_ADD_SEL_ENTRY_CMD			0x44 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_PARTIAL_ADD_SEL_ENTRY_CMD		0x45 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_DELETE_SEL_ENTRY_CMD			0x46 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_CLEAR_SEL_CMD				0x47 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SEL_TIME_CMD			0x48 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_SEL_TIME_CMD			0x49 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_AUXILIARY_LOG_STATUS_CMD		0x5a */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SET_AUXILIARY_LOG_STATUS_CMD		0x5b */
};

/* Transport netfn (0x0c) */
static priv_val transport_privs[] =
{
    PRIV_ENTRY(n,n,n,X), /*						0x00 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_LAN_CONFIG_PARMS_CMD		0x01 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_GET_LAN_CONFIG_PARMS_CMD		0x02 */
    PRIV_ENTRY(n,n,X,X), /* IPMI_SUSPEND_BMC_ARPS_CMD			0x03 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_IP_UDP_RMCP_STATS_CMD		0x04 */
    PRIV_ENTRY(n,n,n,X), /*						0x05 */
    PRIV_ENTRY(n,n,n,X), /*						0x06 */
    PRIV_ENTRY(n,n,n,X), /*						0x07 */
    PRIV_ENTRY(n,n,n,X), /*						0x08 */
    PRIV_ENTRY(n,n,n,X), /*						0x09 */
    PRIV_ENTRY(n,n,n,X), /*						0x0a */
    PRIV_ENTRY(n,n,n,X), /*						0x0b */
    PRIV_ENTRY(n,n,n,X), /*						0x0c */
    PRIV_ENTRY(n,n,n,X), /*						0x0d */
    PRIV_ENTRY(n,n,n,X), /*						0x0e */
    PRIV_ENTRY(n,n,n,X), /*						0x0f */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_SERIAL_MODEM_CONFIG_CMD		0x10 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_GET_SERIAL_MODEM_CONFIG_CMD		0x11 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_SERIAL_MODEM_MUX_CMD		0x12 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_GET_TAP_RESPONSE_CODES_CMD		0x13 */
    PRIV_ENTRY(s,s,s,s), /* IPMI_SET_PPP_UDP_PROXY_XMIT_DATA_CMD	0x14 */
    PRIV_ENTRY(s,s,s,s), /* IPMI_GET_PPP_UDP_PROXY_XMIT_DATA_CMD	0x15 */
    PRIV_ENTRY(s,s,s,s), /* IPMI_SEND_PPP_UDP_PROXY_PACKET_CMD		0x16 */
    PRIV_ENTRY(s,s,s,s), /* IPMI_GET_PPP_UDP_PROXY_RECV_DATA_CMD	0x17 */
    PRIV_ENTRY(b,b,b,b), /* IPMI_SERIAL_MODEM_CONN_ACTIVE_CMD		0x18 */
    PRIV_ENTRY(X,n,X,X), /* IPMI_CALLBACK_CMD				0x19 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_USER_CALLBACK_OPTIONS_CMD		0x1a */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_USER_CALLBACK_OPTIONS_CMD		0x1b */
    PRIV_ENTRY(n,n,n,X), /*						0x1c */
    PRIV_ENTRY(n,n,n,X), /*						0x1d */
    PRIV_ENTRY(n,n,n,X), /*						0x1e */
    PRIV_ENTRY(n,n,n,X), /*						0x1f */
    PRIV_ENTRY(b2,b2,b2,b2), /* IPMI_SOL_ACTIVATING_CMD			0x20 */
    PRIV_ENTRY(n,n,n,X), /* IPMI_SET_SOL_CONFIGURATION_PARAMETERS	0x21 */
    PRIV_ENTRY(n,X,X,X), /* IPMI_GET_SOL_CONFIGURATION_PARAMETERS	0x22 */
};

static struct
{
    int      size;
    priv_val *vals;
} priv_table[7] =
{
    { sizeof(chassis_privs)/sizeof(priv_val), chassis_privs },
    { sizeof(bridge_privs)/sizeof(priv_val), bridge_privs },
    { sizeof(sensor_privs)/sizeof(priv_val), sensor_privs },
    { sizeof(app_privs)/sizeof(priv_val), app_privs },
    { sizeof(firmware_privs)/sizeof(priv_val), firmware_privs },
    { sizeof(storage_privs)/sizeof(priv_val), storage_privs },
    { sizeof(transport_privs)/sizeof(priv_val), transport_privs },
};

int
ipmi_cmd_permitted(unsigned char priv,
		   unsigned char netfn,
		   unsigned char cmd)
{
    int      perm;

    /* Priviledges */
    if ((priv < IPMI_PRIVILEGE_CALLBACK) || (priv > IPMI_PRIVILEGE_ADMIN))
	return IPMI_PRIV_INVALID;

    if ((netfn > IPMI_TRANSPORT_NETFN)
	|| (cmd >= priv_table[netfn>>1].size))
    {
	/* All things not in the table are assumed to take
           administrator priviledge. */
	if (priv == IPMI_PRIVILEGE_ADMIN)
	    return IPMI_PRIV_PERMITTED;
	else
	    return IPMI_PRIV_DENIED;
    }

    perm = priv_table[netfn>>1].vals[cmd];
    /* Extract the permissions for the given privilege from the
       permission word.  The tables are 0-based, but the first valid
       privilege is 1, thus the (priv - 1) here. */
    perm >>= 4 * (priv - 1);
    perm &= 0xf;

    switch (perm)
    {
	case n:
	case s:
	case b:
	case b2:
	    return 0;

	case p:
	case X:
	    return IPMI_PRIV_PERMITTED;

	case h:
	    return IPMI_PRIV_SEND;

	case i:
	    return IPMI_PRIV_BOOT;
    }

    return IPMI_PRIV_DENIED;
}
