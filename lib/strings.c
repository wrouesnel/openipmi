/*
 * strings.c
 *
 * MontaVista IPMI code for converting values to strings.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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
#include <stdio.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_mc.h>
#include <string.h>
#include <OpenIPMI/internal/ipmi_malloc.h>

const char *
ipmi_update_e_string(enum ipmi_update_e val)
{
    switch (val) {
    case IPMI_ADDED: return "added";
    case IPMI_DELETED: return "deleted";
    case IPMI_CHANGED: return "changed";
    default: return "invalid";
    }
}

static char *hysteresis_support_types[] =
{
    "none",
    "readable",
    "settable",
    "fixed",
};
#define NUM_HYSTERESIS_SUPPORT_TYPES (sizeof(hysteresis_support_types)/sizeof(char *))
const char *
ipmi_get_hysteresis_support_string(unsigned int val)
{
    if (val >= NUM_HYSTERESIS_SUPPORT_TYPES)
	return "invalid";
    return hysteresis_support_types[val];
}

static char *threshold_access_support_types[] =
{
    "none",
    "readable",
    "settable",
    "fixed",
};
#define NUM_THRESHOLD_ACCESS_SUPPORT_TYPES (sizeof(threshold_access_support_types)/sizeof(char *))
const char *
ipmi_get_threshold_access_support_string(unsigned int val)
{
    if (val >= NUM_THRESHOLD_ACCESS_SUPPORT_TYPES)
	return "invalid";
    return threshold_access_support_types[val];
}

static char *event_support_types[] =
{
    "per_state",
    "entire_sensor",
    "global_disable",
    "none",
};
#define NUM_EVENT_SUPPORT_TYPES (sizeof(event_support_types)/sizeof(char *))
const char *
ipmi_get_event_support_string(unsigned int val)
{
    if (val >= NUM_EVENT_SUPPORT_TYPES)
	return "invalid";
    return event_support_types[val];
}

static char *sensor_types[] =
{
    "unspecified",
    "temperature",
    "voltage",
    "current",
    "fan",
    "physical_security",
    "platform_security",
    "processor",
    "power_supply",
    "power_unit",
    "cooling_device",
    "other_units_based_sensor",
    "memory",
    "drive_slot",
    "power_memory_resize",
    "system_firmware_progress",
    "event_logging_disabled",
    "watchdog_1",
    "system_event",
    "critical_interrupt",
    "button",
    "module_board",
    "microcontroller_coprocessor",
    "add_in_card",
    "chassis",
    "chip_set",
    "other_fru",
    "cable_interconnect",
    "terminator",
    "system_boot_initiated",
    "boot_error",
    "os_boot",
    "os_critical_stop",
    "slot_connector",
    "system_acpi_power_state",
    "watchdog_2",
    "platform_alert",
    "entity_presense",
    "monitor_asic_ic",
    "lan",
    "management_subsystem_health",
    "battery",
    "session_audit",
    "version_change",
    "fru_state",
};
#define NUM_SENSOR_TYPES (sizeof(sensor_types)/sizeof(char *))
const char *
ipmi_get_sensor_type_string(unsigned int val)
{
    if (val >= NUM_SENSOR_TYPES)
	return "invalid";
    return sensor_types[val];
}

static char *event_reading_types[] =
{
    "unspecified",
    "threshold",
    "discrete_usage",
    "discrete_state",
    "discrete_predictive_failure",
    "discrete_limit_exceeded",
    "discrete_performance_met",
    "discrete_severity",
    "discrete_device_presense",
    "discrete_device_enable",
    "discrete_availability",
    "discrete_redundancy",
    "discrete_acpi_power",
};
#define NUM_EVENT_READING_TYPES (sizeof(event_reading_types)/sizeof(char *))
const char *
ipmi_get_event_reading_type_string(unsigned int val)
{
    if (val == IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC)
	return "sensor specific";

    if (val >= NUM_EVENT_READING_TYPES)
	return "invalid";
    return event_reading_types[val];
}

static char *sensor_directions[] =
{
    "unspecified",
    "input",
    "output",
};
#define NUM_SENSOR_DIRECTIONS (sizeof(sensor_directions)/sizeof(char *))
const char *
ipmi_get_sensor_direction_string(unsigned int val)
{
    if (val >= NUM_SENSOR_DIRECTIONS)
	return "invalid";
    return sensor_directions[val];
}

static char *rate_unit_types[] =
{
    "",
    "/us",
    "/ms",
    "/sec",
    "/min",
    "/hour",
    "/day",
};
#define NUM_RATE_UNIT_TYPES (sizeof(rate_unit_types)/sizeof(char *))
const char *
ipmi_get_rate_unit_string(unsigned int val)
{
    if (val >= NUM_RATE_UNIT_TYPES)
	return "invalid";
    return rate_unit_types[val];
}

static char *unit_types[] =
{
    "unspecified",
    "C",
    "F",
    "K",
    "volts",
    "amps",
    "watts",
    "joules",
    "coulombs",
    "VA",
    "nits",
    "lumens",
    "lux",
    "candela",
    "kpa",
    "PSI",
    "newtons",
    "CFM",
    "RPM",
    "HZ",
    "useconds",
    "mseconds",
    "seconds",
    "minute",
    "hour",
    "day",
    "week",
    "mil",
    "inches",
    "feet",
    "cubic inchs",
    "cubic feet",
    "millimeters",
    "centimeters",
    "meters",
    "cubic centimeters"
    "cubic meters",
    "liters",
    "fluid ounces",
    "radians",
    "seradians",
    "revolutions",
    "cycles",
    "gravities",
    "ounces",
    "pounds",
    "foot pounds",
    "ounce inches",
    "gauss",
    "gilberts",
    "henries",
    "mhenries",
    "farads",
    "ufarads",
    "ohms",
    "siemens",
    "moles",
    "becquerels",
    "PPM",
    "unspecified",
    "decibels",
    "DbA",
    "DbC",
    "grays",
    "sieverts",
    "color temp deg K",
    "bits",
    "kbits",
    "mbits",
    "gbits",
    "bytes",
    "kbytes",
    "mbytes",
    "gbytes",
    "words",
    "dwords",
    "qwords",
    "lines",
    "hits",
    "misses",
    "retries",
    "resets",
    "overruns",
    "underruns",
    "collisions",
    "packets",
    "messages",
    "characters",
    "errors",
    "correctable_errors",
    "uncorrectable_errors",
    "fatal errors",
    "grams",
};
#define NUM_UNIT_TYPES (sizeof(unit_types)/sizeof(char *))
const char *
ipmi_get_unit_type_string(unsigned int val)
{
    if (val >= NUM_UNIT_TYPES)
	return "invalid";
    return unit_types[val];
}

static char *threshold_types[] =
{
    "lower non-critical",
    "lower critical",
    "lower non-recoverable",
    "upper non-critical",
    "upper critical",
    "upper non-recoverable"
};
#define NUM_THRESHOLD_TYPES (sizeof(threshold_types)/sizeof(char *))
const char *
ipmi_get_threshold_string(enum ipmi_thresh_e val)
{
    if (val > NUM_THRESHOLD_TYPES)
	return "invalid";
    return threshold_types[val];
}

static char *value_dir_types[] =
{
    "going-low",
    "going-high"
};
#define NUM_VALUE_DIR_TYPES (sizeof(value_dir_types)/sizeof(char *))
const char *
ipmi_get_value_dir_string(enum ipmi_event_value_dir_e val)
{
    if (val > NUM_VALUE_DIR_TYPES)
	return "invalid";
    return value_dir_types[val];
}

static char *event_dir_types[] =
{
    "assertion",
    "deassertion"
};
#define NUM_EVENT_DIR_TYPES (sizeof(event_dir_types)/sizeof(char *))
const char *
ipmi_get_event_dir_string(enum ipmi_event_dir_e val)
{
    if (val > NUM_EVENT_DIR_TYPES)
	return "invalid";
    return event_dir_types[val];
}

static char *entity_id_types[] =
{
    "unspecified",					/* 0 */
    "other",
    "unkown",
    "processor",
    "disk",
    "peripheral",
    "system_management_module",
    "system_board",
    "memory_module",
    "processor_module",
    "power_supply",					/* 10 */
    "add_in_card",
    "front_panel_board",
    "back_panel_board",
    "power_system_board",
    "drive_backplane",
    "system_internal_expansion_board",
    "other_system_board",
    "processor_board",
    "power_unit",
    "power_module",					/* 20 */
    "power_management_board",
    "chassis_back_panel_board",
    "system_chassis",
    "sub_chassis",
    "other_chassis_board",
    "disk_drive_bay",
    "peripheral_bay",
    "device_bay",
    "fan_cooling",
    "cooling_unit",					/* 30 */
    "cable_interconnect",
    "memory_device",
    "system_management_software",
    "bios",
    "operating_system",
    "system_bus",
    "group",
    "remote_mgmt_comm_device",
    "external_environment",
    "battery",						/* 40 */
    "processing blade",
    "connectivity switch",
    "processor/memory module",
    "I/O module",
    "processor I/O module",
    "management controller firmware",
    "ipmi channel",
    "pci bus",
    "pci express bus",
    "scsi bus",						/* 50 */
    "sata/sas bus",
    "processor front side bus",
};
#define NUM_ENTITY_ID_TYPES (sizeof(entity_id_types)/sizeof(char *))
const char *
ipmi_get_entity_id_string(unsigned int val)
{
    if (val >= NUM_ENTITY_ID_TYPES)
	return "invalid";
    return entity_id_types[val];
}

static char *event_reading_states[256][16] =
{
    { },
    { "lower non-critical - going low",
      "lower non-critical - going high",
      "lower critical - going low",
      "lower critical - going high",
      "lower non-recoverable - going low",
      "lower non-recoverable - going high",
      "upper non-critical - going low",
      "upper non-critical - going high",
      "upper critical - going low",
      "upper critical - going high",
      "upper non-recoverable - going low",
      "upper non-recoverable - going high", },
    { "transition to idle", "transition to active", "transition to busy" },
    { "state deasserted", "state asserted" },
    { "predictive failure deasserted", "predictive failure asserted" },
    { "limit not exceeded", "limit exceeded" },
    { "performance met", "performance lags" },
    { "transition to ok",
      "transition to non-critical from ok",
      "transition to critical from ok",
      "transition to non-recoverable from less severe",
      "transition to non-critical from more severe",
      "transition to critical from non-recoverable",
      "transition to non-recoverable",
      "monitor",
      "informational", },
    { "device removed/absent", "device inserted/present" },
    { "device disabled", "device enabled" },
    { "transition to ",
      "transition to in test",
      "transition to power off",
      "transition to on line",
      "transition to off line",
      "transition to off duty",
      "transition to degraded",
      "transition to power save",
      "install error" },
    { "fully redundant",
      "redundancy lost",
      "redundancy degraded",
      "non-redundant: sufficient resources from redundant",
      "non-redundant: sufficient resources from insufficient resources",
      "non-redundant: insufficient resources",
      "redundancy degraded from fully redundant",
      "redundancy degraded from non-redundant" },
    { "D0 power state",
      "D1 power state",
      "D2 power state",
      "D3 power state" }
};

static char *sensor_states[256][16] =
{
    {}, /* 0x00 */
    {}, /* 0x01 */
    {}, /* 0x02 */
    {}, /* 0x03 */
    {}, /* 0x04 */
    { /* 0x05 */
	"general chassis intrusion",
	"drive bay intrusion",
	"I/O card area intrusion",
	"processor area intrusion",
	"LAN leash lost",
	"unauthorized doc/undock",
	"fan area intrusion"
    },
    { /* 0x06 */
	"secure mode",
	"pre-boot password violation - user password",
	"pre-boot password violation - setup password",
	"pre-boot password violation - network boot password",
	"other pre-boot password violation",
	"out-of-band access password violation",
    },
    { /* 0x07 */
	"IERR",
	"Thermal Trip",
	"FRB1/BIST failure",
	"FRB2/Hand in POST failure",
	"FRB3/Processor startup/initialization failure",
	"configuration error",
	"SM BIOS 'uncorrectable CPU-complex error'",
	"processor presence detected",
	"processor disabled",
	"terminator presence detected"
    },
    { /* 0x08 */
	"presence detected",
	"power supply failure detected",
	"predictive failure",
	"power supply AC lost",
	"AC lost or out-of-range",
	"AC out of range, but present"
    },
    { /* 0x09 */
	"power off/power down",
	"power cycle",
	"240VA power down",
	"interlock power down",
	"AC lost",
	"soft power control failure",
	"power unit falure detected",
	"predictive failure",
    },
    {}, /* 0x0a */
    {}, /* 0x0b */
    { /* 0x0c */
	"correctable ECC",
	"uncorrectable ECC",
	"parity",
	"memory scrub failed (stuck bit)",
	"memory device disabled",
	"correctable ECC log limit reached",
	"presence detected",
	"configuration error",
	"spare",
	"memory automatically throttled",
    },
    { /* 0x0d */
	"drive presence",
	"drive fault",
	"predictive failure",
	"hot spare",
	"consistancy/parity check in progress",
	"in critical array",
	"in failed array",
	"rebuild/remap in progress",
	"rebuild/remap aborted",
    },
    {}, /* 0x0e */
    { /* 0x0f */
	"system firmware error",
	"system firmware hang",
	"system firmware progress"
    },
    { /* 0x10 */
	"correctable memory error logging disabled",
	"event type logging siabled",
	"log area reset/cleared",
	"all event logging disabled",
    },
    { /* 0x11 */
	"BIOS watchdog reset",
	"OS watchdog reset",
	"os watchdog shutdown",
	"os watchdog power down",
	"os watchdog power cycle",
	"os watchdog NMI/diag interrupt",
	"os watchdog expired",
	"os watchdog pretimout interrupt",
    },
    { /* 0x12 */
	"system reconfigured",
	"OEM system boot event",
	"undetermined system hardware failure",
	"entry added to auxiliary log",
	"PEF action",
	"Timestamp clock sync"
    },
    { /* 0x13 */
	"front panel NMI/diag interrupt",
	"bus timeout",
	"I/O channel check NMI",
	"software NMI",
	"PCI PERR",
	"PCI SERR",
	"EISA fail safe timeout",
	"bus correctable error",
	"bus uncorrectable error",
	"fatal NMI"
    },
    { /* 0x14 */
	"power button pressed",
	"sleep button pressed",
	"reset button pressed"
    },
    {}, /* 0x15 */
    {}, /* 0x16 */
    {}, /* 0x17 */
    {}, /* 0x18 */
    {}, /* 0x19 */
    {}, /* 0x1a */
    { /* 0x1b */
	"cable/interconnect is connected",
	"configuration error",
    },
    {}, /* 0x1c */
    { /* 0x1d */
	"initiated by power up",
	"initiated by hard reset",
	"initiated by warm reset",
	"user requested PXE boot",
	"automatic boot to diagnostic",
	"OS initiated hard reset",
	"OS initiated warm reset",
	"System restart",
    },
    { /* 0x1e */
	"no bootable media",
	"non-bootable diskette left in drive",
	"PXE server not found",
	"invalid boot sector",
	"timeout waiting for user selection of boot source"
    },
    { /* 0x1f */
	"A: boot completed",
	"C: boot completed",
	"PXE boot completed",
	"diagnostic boot completed",
	"CD-ROM boot completed",
	"ROM boot completed",
	"boot completed"
    },
    { /* 0x20 */
	"stop during OS load/initialization",
	"run time critical stop",
	"OS Graceful Stop",
	"Soft shutdown initiated by PEF",
	"Agent not responding, graceful shutdown did not occur"
    },
    { /* 0x21 */
	"fault status asserted",
	"identify status asserted",
	"slot/connector device installed/attached",
	"slot/connector ready for device installation",
	"slot/connector ready for device removal",
	"slot power is off",
	"slot/connector device removal request",
	"interlock asserted",
	"slot is disabled"
    },
    { /* 0x22 */
	"S0/G0 working",
	"S1 'Sleeping with system H/W & processor context maintained'",
	"S2 'sleeping, processor context lost'",
	"S3 'sleeping, processor & h/w context lost, memory retained'",
	"S4 'non-volatile sleep/suspend to disk'",
	"S5/G2 soft-off",
	"S4/S5 soft-off"
	"G3 mechanical off",
	"sleeping in an S1, S2, or S3 state",
	"G1 sleeping",
	"S5 entered by override",
	"legacy on state",
	"legacy off state",
	NULL,
	"unknown"
    },
    { /* 0x23 */
	"timer expired",
	"hard reset",
	"power down",
	"power cycle",
	NULL,
	NULL,
	NULL,
	NULL,
	"timer interrupt"
    },
    { /* 0x24 */
	"platform generated page",
	"platform generated LAN alert",
	"platform event trap generated",
	"platform generated SNMP trap"
    },
    { /* 0x25 */
	"entity present",
	"entity absent",
	"entity disabled"
    },
    {}, /* 0x26 */
    { /* 0x27 */
	"LAN heartbeat lost",
	"LAN heartbeat"
    },
    { /* 0x28 */
	"sensor access degraded or unavailable",
	"controller access degraded or unavailable",
	"management controller off-line",
	"management controller unavailable",
	"sensor failure",
	"FRU failure"
    },
    { /* 0x29 */
	"battery low",
	"battery failed",
	"battery presence detected"
    },
};

const char *
ipmi_get_reading_name(unsigned int event_reading_type,
		      unsigned int sensor_type,
		      unsigned int val)
{
    char *rv;
    if (event_reading_type == IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC) {
	if ((sensor_type > 255) || (val > 15))
	    return "invalid";
	rv = sensor_states[sensor_type][val];
    } else {
	if ((event_reading_type > 255) || (val > 15))
	    return "invalid";
	rv = event_reading_states[event_reading_type][val];
    }
    if (rv == NULL)
	return "unknown";
    return rv;
}

static char *control_types[] =
{
    "unspecified",
    "light",
    "relay",
    "display",
    "alarm",
    "reset",
    "power",
    "fan speed",
    "identifier",
    "one-shot reset",
    "output",
    "one-shot output",
};
#define NUM_CONTROL_TYPES (sizeof(control_types)/sizeof(char *))
const char *
ipmi_get_control_type_string(unsigned int val)
{
    if (val >= NUM_CONTROL_TYPES)
	return "invalid";
    return control_types[val];
}

static char *colors[] =
{
    "black",
    "white",
    "red",
    "green",
    "blue",
    "yellow",
    "orange",
};
#define NUM_COLORS (sizeof(colors)/sizeof(char *))
const char *
ipmi_get_color_string(unsigned int val)
{
    if (val >= NUM_COLORS)
	return "invalid";
    return colors[val];
}

static char *ipmi_netfns[] =
{
    "chassis(c):%02x",		// +0 : 0x00
    "chassis(r):%02x",		// +1 : 0x01
    "bridge(c):%02x",		// +2 : 0x02
    "bridge(r):%02x",		// +3 : 0x03
    "s/e(c):%02x",		// +4 : 0x04
    "s/e(r):%02x",		// +5 : 0x05
    "app(c):%02x",		// +6 : 0x06
    "app(r):%02x",		// +7 : 0x07
    "firmware(c):%02x",		// +8 : 0x08
    "firmware(r):%02x",		// +9 : 0x09
    "storage(c):%02x",		// +10: 0x0a
    "storage(r):%02x",		// +11: 0x0b
    "transport(c):%02x",	// +12: 0x0c
    "transport(r):%02x",	// +13: 0x0d
    "reserved(c):%02x",		// +14: 0x0e..0x2b reserved
    "reserved(r):%02x",		// +15: 0x2b
    "grpext(c):%02x",		// +16: 0x2c
    "grpext(r):%02x",		// +17: 0x2d
    "oem/grp(c):%02x",		// +18: 0x2e
    "oem/grp(r):%02x",		// +19: 0x2f
    "ctlrspec(c):%02x",		// +20: 0x30..3f Controller specific
    "ctlrspec(r):%02x",		// +21: 0x3f
};
/*
 * Convert a NetFN code into a string
 */
char *
ipmi_get_netfn_string(unsigned int netfn,
		      char         *buffer,
		      unsigned int buf_len)
{
    char *netfn_fs;

    netfn &= 0x3f;

    if ( netfn > 0x2f )
	netfn_fs = ipmi_netfns[(netfn & 0x01) + 20];
    else if ( netfn > 0x2d )
	netfn_fs = ipmi_netfns[(netfn & 0x01) + 18];
    else if ( netfn > 0x2b )
	netfn_fs = ipmi_netfns[(netfn & 0x01) + 16];
    else if ( netfn > 0x0d )
	netfn_fs = ipmi_netfns[(netfn & 0x01) + 14];
    else
	netfn_fs = ipmi_netfns[netfn];

    snprintf(buffer, buf_len, netfn_fs, netfn);

    return buffer;
}

static char * ipmi_app_cmds[] =
{
    "reserved:%02x",		// +0 : 0x00
    "GetDevId:%02x",		// +1 : 0x01
    "ColdReset:%02x",		// +2 : 0x02
    "WarmReset:%02x",		// +3 : 0x03
    "GetSelfTest:%02x",		// +4 : 0x04
    "ManuTestOn:%02x",		// +5 : 0x05
    "SetACPIpwr:%02x",		// +6 : 0x06
    "GetACPIpwr:%02x",		// +7 : 0x07
    "GetDevGUID:%02x",		// +8 : 0x08 (0x09..0x21 unassigned)
    "ResetWdog:%02x",		// +9 : 0x22
    "unassigned:%02x",		// +10: 0x23 unassigned
    "SetWdog:%02x",		// +11: 0x24
    "GetWdog:%02x",		// +12: 0x25 (0x26..0x2d unassigned)
    "SetBMCgblEna:%02x",	// +13: 0x2e
    "GetBMCgblEna:%02x",	// +14: 0x2f
    "ClrMsgFlags:%02x",		// +15: 0x30
    "GetMsgFlags:%02x",		// +16: 0x31
    "EnaMsgChRcv:%02x",		// +17: 0x32
    "GetMsg:%02x",		// +18: 0x33
    "SndMsg:%02x",		// +19: 0x34
    "ReadEvntMsg:%02x",		// +20: 0x35
    "GetBTifCap:%02x",		// +21: 0x36
    "GetSysGUID:%02x",		// +22: 0x37
    "GetChAuthCap:%02x",	// +23: 0x38
    "GetSessChlng:%02x",	// +24: 0x39
    "ActiSess:%02x",		// +25: 0x3a
    "SetSessPrivlvl:%02x",	// +26: 0x3b
    "CloseSess:%02x",		// +27: 0x3c
    "GetSessInfo:%02x",		// +28: 0x3d
    "unassigned:%02x",		// +29: 0x3e unassigned
    "GetAuthCode:%02x",		// +30: 0x3f
    "SetChAccess:%02x",		// +31: 0x40
    "GetChAccess:%02x",		// +32: 0x41
    "GetChInfoCmd:%02x",	// +33: 0x42
    "SetUsrAccCmd:%02x",	// +34: 0x43
    "GetUsrAccCmd:%02x",	// +35: 0x44
    "SetUsrName:%02x",		// +36: 0x45
    "GetUsrName:%02x",		// +37: 0x46
    "SetUsrPasswd:%02x",	// +38: 0x47
    "ActPayload:%02x",		// +39: 0x48
    "DeactPayload:%02x",	// +40: 0x49
    "GetPayloadActStat:%02x",	// +41: 0x4a
    "GetPayloadInstInfo:%02x",	// +42: 0x4b
    "SetUserPayloadAcc:%02x",	// +43: 0x4c
    "GetUserPayloadAcc:%02x",	// +44: 0x4d
    "GetChanPayloadSup:%02x",	// +45: 0x4e
    "GetChanPayloadVer:%02x",	// +46: 0x4f
    "GetChanOEMPayloadInf:%02x",// +47: 0x50
    "unassigned:%02x",		// +48: 0x51 unassigned
    "MstrWrRd:%02x",		// +49: 0x52
    "unassigned:%02x",		// +50: 0x53 unassigned
    "GetChanCipherSuites:%02x",	// +51: 0x54
    "SuspResPayloadEnc:%02x",	// +52: 0x55
    "SetChanSecKey:%02x",	// +53: 0x56
    "GetSysIntfCap:%02x",	// +54: 0x57
};

static char * ipmi_chassis_cmds[] =
{
    "GetChassisCap:%02x",	// +0 : 0x00
    "GetChassisSts:%02x",	// +1 : 0x01
    "ChassisCtrl:%02x",		// +2 : 0x02
    "ChassisReset:%02x",	// +3 : 0x03
    "ChassisIdent:%02x",	// +4 : 0x04
    "SetChassisCap:%02x",	// +5 : 0x05
    "SetPwrRestPol:%02x",	// +6 : 0x06
    "GetSysRstCause:%02x",	// +7 : 0x07
    "SetSysBootOp:%02x",	// +8 : 0x08
    "GetSysBootOp:%02x",	// +9 : 0x09
    "unassigned:%02x",		// +10: 0x0a..0x0e unassigned
    "GetPOHcounter:%02x",	// +11: 0x0f
};

static char * ipmi_se_cmds[] =
{
    "SetEvntRcvr:%02x",		// +0 : 0x00
    "GetEvntRcvr:%02x",		// +1 : 0x01
    "EventMsg:%02x",		// +2 : 0x02 (0x03..0x0f unassigned)
    "GetPEFcap:%02x",		// +3 : 0x10
    "ArmPEFtimer:%02x",		// +4 : 0x11
    "SetPEFconfig:%02x",	// +5 : 0x12
    "GetPEFconfig:%02x",	// +6 : 0x13
    "SetLastEvId:%02x",		// +7 : 0x14
    "GetLastEvId:%02x",		// +8 : 0x15
    "AlertImmed:%02x",		// +9 : 0x16
    "PETackn:%02x",		// +10: 0x17 (0x18..0x1f unassigned)
    "GetDevSDRinfo:%02x",	// +11: 0x20
    "GetDevSDR:%02x",		// +12: 0x21
    "ReservSDRreposit:%02x",	// +13: 0x22
    "GetSensReadFact:%02x",	// +14: 0x23
    "SetSensHyst:%02x",		// +15: 0x24
    "GetSensHyst:%02x",		// +16: 0x25
    "SetSensThresh:%02x",	// +17: 0x26
    "GetSensThresh:%02x",	// +18: 0x27
    "SetSensEvEna:%02x",	// +29: 0x28
    "GetSensEvEna:%02x",	// +20: 0x29
    "RearmSensEv:%02x",		// +21: 0x2a
    "GetSensEvStat:%02x",	// +22: 0x2b
    "unassigned:%02x",		// +23: 0x2c unassigned
    "GetSensReading:%02x",	// +24: 0x2d
    "SetSensType:%02x",		// +25: 0x2e
    "GetSensType:%02x",		// +26: 0x2f
};

static char * ipmi_storage_cmds[] =
{
    "unassigned:%02x",		// +0 : 0x00..0x0f unassigned
    "GetFRUinvInfo:%02x",	// +1 : 0x10
    "ReadFRUdata:%02x",		// +2 : 0x11
    "WriteFRUdata:%02x",	// +3 : 0x12 (0x13..0x1f unassigned)
    "GetSDRrepInfo:%02x",	// +4 : 0x20
    "GetSDRrepAlloc:%02x",	// +5 : 0x21
    "ResrvSDRrepo:%02x",	// +6 : 0x22
    "GetSDR:%02x",		// +7 : 0x23
    "AddSDR:%02x",		// +8 : 0x24
    "PartialAddSDR:%02x",	// +9 : 0x25
    "DeleteSDR:%02x",		// +10: 0x26
    "ClrSDRrepo:%02x",		// +11: 0x27
    "GetSDRrepTime:%02x",	// +12: 0x28
    "SetSDRrepTime:%02x",	// +13: 0x29
    "EntrSDRrepUpd:%02x",	// +14: 0x2a
    "ExitSDRrepUpd:%02x",	// +15: 0x2b
    "RunInitAgent:%02x",	// +16: 0x2c (0x2d..0x3f unassigned)
    "GetSELinfo:%02x",		// +17: 0x40
    "GetSELallocInfo:%02x",	// +18: 0x41
    "ReservSEL:%02x",		// +19: 0x42
    "GetSELentry:%02x",		// +20: 0x43
    "AddSELentry:%02x",		// +21: 0x44
    "PartAddSELentry:%02x",	// +22: 0x45
    "DeleteSELent:%02x",	// +23: 0x46
    "ClrSEL:%02x",		// +24: 0x47
    "GetSELtime:%02x",		// +25: 0x48
    "SetSELtime:%02x",		// +26: 0x49 (0x4a..0x59 unassigned)
    "GetAuxLogSts:%02x",	// +27: 0x5a
    "SetAuxLogSts:%02x",	// +28: 0x5b
};

static char * ipmi_transport_cmds[] =
{
    "unassigned:%02x",		// +0 : 0x00 unassigned
    "SetLANconfParm:%02x",	// +1 : 0x01
    "GetLANconfParm:%02x",	// +2 : 0x02
    "SuspBMCarps:%02x",		// +3 : 0x03
    "GetIPstats:%02x",		// +4 : 0x04 (0x05..0x0f unassigned)
    "SetSerialConf:%02x",	// +5 : 0x10
    "GetSerialConf:%02x",	// +6 : 0x11
    "SetSerialMux:%02x",	// +7 : 0x12
    "GetTAPrespCodes:%02x",	// +8 : 0x13
    "SetPPPproxyTx:%02x",	// +9 : 0x14
    "GetPPPproxyTx:%02x",	// +10: 0x15
    "SendPPPproxyPkt:%02x",	// +11: 0x16
    "GetPPPproxyRxData:%02x",	// +12: 0x17
    "SerialConnAct:%02x",	// +13: 0x18
    "Callback:%02x",		// +14: 0x19
    "SetUsrCallOpts:%02x",	// +15: 0x1a
    "GetUsrCallOpts:%02x",	// +16: 0x1b
    "unassigned:%02x",		// +17: 0x1c
    "unassigned:%02x",		// +18: 0x1d
    "unassigned:%02x",		// +19: 0x1e
    "unassigned:%02x",		// +20: 0x1f
    "SOLActivating:%02x",	// +21: 0x20
    "SetSOLConfParm:%02x",	// +22: 0x21
    "GetSOLConfParm:%02x",	// +23: 0x22
};

static char * ipmi_bridge_cmds[] =
{
    "GetBridgeState:%02x",	// +0 : 0x00
    "SetBridgeState:%02x",	// +1 : 0x01
    "GetICMBaddr:%02x",		// +2 : 0x02
    "SetICMBaddr:%02x",		// +3 : 0x03
    "SetBridgeProxyAddr:%02x",	// +4 : 0x04
    "GetBridgeStats:%02x",	// +5 : 0x05
    "GetICMBcaps:%02x",		// +6 : 0x06
    "unassigned:%02x",		// +7 : 0x07 unassigned
    "ClrBridgeStats:%02x",	// +8 : 0x08
    "GetBridgeProxyAddr:%02x",	// +9 : 0x09
    "GetICMBConnInfo:%02x",	// +10: 0x0a
    "GetICMBConnId:%02x",	// +11: 0x0b
    "SendICMBConnId:%02x",	// +12: 0x0c (0x0d..0x0f unassigned)
    "Prep4Disc:%02x",		// +13: 0x10
    "GetAddresses:%02x",	// +14: 0x11
    "SetDiscovered:%02x",	// +15: 0x12
    "GetChassDevId:%02x",	// +16: 0x13
    "SetChassDevId:%02x",	// +17: 0x14 (0x15..0x1f unassigned)
    "BridgeRequest:%02x",	// +18: 0x20
    "BridgeMessage:%02x",	// +19: 0x21 (0x22..0x2f unassigned)
    "GetEventCnt:%02x",		// +20: 0x30
    "SetEventDest:%02x",	// +21: 0x31
    "SetEventRecpState:%02x",	// +22: 0x32
    "SndICMBevMsg:%02x",	// +23: 0x33
    "GetEventDest:%02x",	// +24: 0x34
    "GetEventRecpState:%02x",	// +25: 0x35 (0x36..0xbf unassigned)
    "OEMcommands:%02x",		// +26: 0xc0..0xfe
    "ErrorReport:%02x",		// +27: 0xff
};

/*
 * Convert a NetFN/Command code into a string
 */
char *
ipmi_get_command_string(unsigned int netfn,
			unsigned int cmd,
			char         *buffer,
			unsigned int buf_len)
{
    char **netfn_table;
    char *cmd_fs = NULL;
 
    netfn &= 0x3f;

    if ( netfn <= 0x0d ) {
	switch ( netfn ) {
	    case IPMI_CHASSIS_NETFN:
	    case IPMI_CHASSIS_NETFN | 1:
	    {
		netfn_table=ipmi_chassis_cmds;
		if ( cmd < 0x0b )
		    cmd_fs = netfn_table[cmd];
		else if ( cmd == 0x0f )
		    cmd_fs = netfn_table[11];
		break;
	    }
	    case IPMI_BRIDGE_NETFN:
	    case IPMI_BRIDGE_NETFN | 1:
	    {
		netfn_table=ipmi_bridge_cmds;
		if ( cmd < 0x0d )
		    cmd_fs = netfn_table[cmd];
		else if ( (cmd > 0x0f) && (cmd < 0x15) )
		    cmd_fs = netfn_table[cmd - 0x10 + 13];
		else if ( (cmd > 0x1f) && (cmd < 0x22) )
		    cmd_fs = netfn_table[cmd - 0x20 + 18];
		else if ( (cmd > 0x2f) && (cmd < 0x36) )
		    cmd_fs = netfn_table[cmd - 0x30 + 20];
		else if ( (cmd > 0xbf) && (cmd < 0xff) )
		    cmd_fs = netfn_table[26];
		break;
	    }
	    case IPMI_SENSOR_EVENT_NETFN:
	    case IPMI_SENSOR_EVENT_NETFN | 1:
	    {
		netfn_table=ipmi_se_cmds;
		if ( cmd < 0x03 )
		    cmd_fs = netfn_table[cmd];
		else if ( (cmd > 0x0f) && (cmd < 0x18) )
		    cmd_fs = netfn_table[cmd - 0x10 + 3];
		else if ( (cmd > 0x1f) && (cmd < 0x30) )
		    cmd_fs = netfn_table[cmd - 0x20 + 11];
		break;
	    }
	    case IPMI_APP_NETFN:
	    case IPMI_APP_NETFN | 1:
	    {
		netfn_table=ipmi_app_cmds;
		if ( cmd < 0x09 )
		    cmd_fs = netfn_table[cmd];
		else if ( (cmd > 0x21) && (cmd < 0x26) )
		    cmd_fs = netfn_table[cmd - 0x22 + 9];
		else if ( (cmd > 0x2d) && (cmd < 0x58) )
		    cmd_fs = netfn_table[cmd - 0x2e + 13];
		break;
	    }
	    case IPMI_FIRMWARE_NETFN:
	    case IPMI_FIRMWARE_NETFN | 1:
	    {
		cmd_fs="unknown:%02x";
		break;
	    }
	    case IPMI_STORAGE_NETFN:
	    case IPMI_STORAGE_NETFN | 1:
	    {
		netfn_table=ipmi_storage_cmds;
		if ( cmd < 0x10 )
		    cmd_fs = netfn_table[0];
		else if ( (cmd > 0x0f) && (cmd < 0x13) )
		    cmd_fs = netfn_table[cmd - 0x10 + 1];
		else if ( (cmd > 0x1f) && (cmd < 0x2d) )
		    cmd_fs = netfn_table[cmd - 0x20 + 4];
		else if ( (cmd > 0x3f) && (cmd < 0x4a) )
		    cmd_fs = netfn_table[cmd - 0x40 + 17];
		else if ( (cmd > 0x59) && (cmd < 0x5c) )
		    cmd_fs = netfn_table[cmd - 0x5a + 27];
		break;
	    }
	    case IPMI_TRANSPORT_NETFN:
	    case IPMI_TRANSPORT_NETFN | 1:
	    {
		netfn_table=ipmi_transport_cmds;
		if ( cmd < 0x05 )
		    cmd_fs = netfn_table[cmd];
		else if ( (cmd > 0x0f) && (cmd < 0x23) )
		    cmd_fs = netfn_table[cmd - 0x10 + 5];
		break;
	    }
	}
    }

    if (!cmd_fs)
	cmd_fs = "unknown:%02x";

    snprintf(buffer, buf_len, cmd_fs, cmd);

    return buffer;
}

static char *ipmi_ccodes[] =
{
    "Normal:%02x",	// +0 : 0x00 (0x01..0xbf undefined)
    "NodeBusy:%02x",	// +1 : 0xc0
    "InvCmd:%02x",	// +2 : 0xc1
    "InvCmd4LUN:%02x",	// +3 : 0xc2
    "Timeout:%02x",	// +4 : 0xc3
    "OutOfSpace:%02x",	// +5 : 0xc4
    "ResvCancInv:%02x",	// +6 : 0xc5
    "DataTrunc:%02x",	// +7 : 0xc6
    "DataLenInv:%02x",	// +8 : 0xc7
    "DataLenOvr:%02x",	// +9 : 0xc8
    "PrmRangeErr:%02x",	// +10: 0xc9
    "InsuffData:%02x",	// +11: 0xca
    "ObjNotPres:%02x",	// +12: 0xcb
    "InvDataFld:%02x",	// +13: 0xcc
    "IllCmd4Obj:%02x",	// +14: 0xcd
    "NoResponse:%02x",	// +15: 0xce
    "DupReq:%02x",	// +16: 0xcf
    "SDRrepoBusy:%02x",	// +17: 0xd0
    "FirmwareUpd:%02x",	// +18: 0xd1
    "BMCiniting:%02x",	// +19: 0xd2
    "DestUnavail:%02x",	// +20: 0xd3
    "PrivError:%02x",	// +21: 0xd4
    "InvalState:%02x",	// +22: 0xd5 (0xd6..0xfe undefined)
    "Unspecified:%02x",	// +23: 0xff
};
/*
 * Convert a Completion Code into a string
 */
char *
ipmi_get_cc_string(unsigned int cc,
		   char         *buffer,
		   unsigned int buf_len)
{
    char *cc_fs;

    if ( cc == 0x00 )
	cc_fs = ipmi_ccodes[0];
    else if ( (cc > 0xbf) && (cc < 0xd6) )
	cc_fs = ipmi_ccodes[cc - 0xc0 + 1];
    else if ( cc == 0xff )
	cc_fs = ipmi_ccodes[23];
    else
	cc_fs = "Unknown:%02x";

    snprintf(buffer, buf_len, cc_fs, cc);

    return buffer;
}

int
ipmi_get_cc_string_len(unsigned int cc)
{
    char *cc_fs;
    char dummy[1];

    if ( cc == 0x00 )
	cc_fs = ipmi_ccodes[0];
    else if ( (cc > 0xbf) && (cc < 0xd6) )
	cc_fs = ipmi_ccodes[cc - 0xc0 + 1];
    else if ( cc == 0xff )
	cc_fs = ipmi_ccodes[23];
    else
	cc_fs = "Unknown:%02x";

    return snprintf(dummy, 1, cc_fs, cc);
}


static const char *sol_error_codes[] =
{
    "SoLCharTransUnavail",
    "SoLDeactivated",
    "SoLNotAvailable",
    "SoLDisconnected",
    "SoLUnconfirmOp",
    "SoLFlushed",
    "SoLUnknown"
};

static const char *rmcpp_error_codes[] =
{
    "InsufResourForSess",
    "InvalSessID",
    "InvalPayloadType",
    "InvalAuthAlg",
    "InvalIntegAlg",
    "NoMatchAuthPayld",
    "NoMatchIntegPayld",
    "InactSessID",
    "InvalidRole",
    "UnauthRoleOrPriv",
    "InsufResourForRole",
    "InvalNameLength",
    "UnauthName",
    "UnauthGUID",
    "InvalIntegChkVal",
    "InvalConfidAlg",
    "NoCipherSuiteMatch",
    "IllegalParam",
    "RMCPPUnknown"
};

char *
ipmi_get_error_string(unsigned int err,
		      char         *buffer,
		      unsigned int buf_len)
{
    unsigned int len;
    char         *err_type;

    if (err == 0) {
	strncpy(buffer, "Success (No error)", buf_len);
	return buffer;
    }

    if (IPMI_IS_OS_ERR(err)) {
	snprintf(buffer+4, buf_len-4, "%s", strerror(IPMI_GET_OS_ERR(err)));
	err_type = "OS: ";
    } else if (IPMI_IS_IPMI_ERR(err)) {
	ipmi_get_cc_string(IPMI_GET_IPMI_ERR(err), buffer+6, buf_len-6);
	err_type = "IPMI: ";
    } else if (IPMI_IS_RMCPP_ERR(err)) {
	int rmcpp_err = IPMI_GET_RMCPP_ERR(err);
	if ((rmcpp_err <= 0) && (rmcpp_err > 0x12))
	    rmcpp_err = 0x13;
	snprintf(buffer+7, buf_len-7, "%s (0x%02x)",
		 rmcpp_error_codes[rmcpp_err - 1],
		 IPMI_GET_RMCPP_ERR(err));
	err_type = "RMCP+: ";
    } else if (IPMI_IS_SOL_ERR(err)) {
	int sol_err = IPMI_GET_SOL_ERR(err);
	if ((sol_err < 1) || (sol_err > 7))
	    sol_err = 7;
	strncpy(buffer+5, sol_error_codes[sol_err - 1], buf_len-5);
	err_type = "SoL: ";
    } else {
	strncpy(buffer+9, "Unknown", buf_len-9);
	err_type = "Unknown: ";
    }

    len = strlen(err_type);
    if (len > buf_len-1) {
	len = buf_len-1;
	buffer[buf_len-1] = '\0';
    }
    memcpy(buffer, err_type, len);

    return buffer;
}

int ipmi_get_error_string_len(unsigned int err)
{
    if (err == 0)
	return(strlen("Success (No error)"));

    if (IPMI_IS_OS_ERR(err))
	return strlen(strerror(IPMI_GET_OS_ERR(err))) + 5;
    else if (IPMI_IS_IPMI_ERR(err)) {
	return ipmi_get_cc_string_len(IPMI_GET_IPMI_ERR(err)) + 7;
    } else if (IPMI_IS_RMCPP_ERR(err)) {
	int rmcpp_err = IPMI_GET_RMCPP_ERR(err);
	if ((rmcpp_err <= 0) && (rmcpp_err > 0x12))
	    rmcpp_err = 0x13;
	return strlen(rmcpp_error_codes[rmcpp_err - 1]) + 15;
    } else if (IPMI_IS_SOL_ERR(err)) {
	int sol_err = IPMI_GET_SOL_ERR(err);
	if ((sol_err < 1) || (sol_err > 7))
	    sol_err = 7;
	return strlen(sol_error_codes[sol_err - 1]) + 6;
    } else {
	return strlen("Unknown") + 10;
    }
}

/* Get a string name fo the hot swap state. */
const char *
ipmi_hot_swap_state_name(enum ipmi_hot_swap_states state)
{
    switch (state) {
    case IPMI_HOT_SWAP_NOT_PRESENT: return "not_present";
    case IPMI_HOT_SWAP_INACTIVE: return "inactive";
    case IPMI_HOT_SWAP_ACTIVATION_REQUESTED: return "activation_requested";
    case IPMI_HOT_SWAP_ACTIVATION_IN_PROGRESS: return "activation_in_progress";
    case IPMI_HOT_SWAP_ACTIVE: return "active";
    case IPMI_HOT_SWAP_DEACTIVATION_REQUESTED: return "deactivation_requested";
    case IPMI_HOT_SWAP_DEACTIVATION_IN_PROGRESS: return "deactivation_in_progress";
    case IPMI_HOT_SWAP_OUT_OF_CON: return "out_of_con";
    default: return "invalid_state";
    }
}

static char *domain_types[] =
{
    "unknown",
    "MXP",
    "ATCA",
    "ATCA_BLADE",
};
#define NUM_DOMAIN_TYPES (sizeof(domain_types)/sizeof(char *))

const char *
ipmi_domain_get_type_string(enum ipmi_domain_type dtype)
{
    if ((dtype < 0) || (dtype >= NUM_DOMAIN_TYPES))
	return "invalid";
    return domain_types[dtype];
}

const char *
ipmi_authtype_string(int authtype)
{
    switch(authtype) {
    case IPMI_AUTHTYPE_DEFAULT:
	return "default";
    case IPMI_AUTHTYPE_NONE:
	return "none";
    case IPMI_AUTHTYPE_MD2:
	return "md2";
    case IPMI_AUTHTYPE_MD5:
	return "md5";
    case IPMI_AUTHTYPE_STRAIGHT:
	return "straight";
    case IPMI_AUTHTYPE_OEM:
	return "oem";
    case IPMI_AUTHTYPE_RMCP_PLUS:
	return "rmcp+";
    default:
	return "invalid";
    }
}

const char *
ipmi_privilege_string(int privilege)
{
    switch(privilege) {
    case IPMI_PRIVILEGE_CALLBACK:
	return "callback";
    case IPMI_PRIVILEGE_USER:
	return "user";
    case IPMI_PRIVILEGE_OPERATOR:
	return "operator";
    case IPMI_PRIVILEGE_ADMIN:
	return "admin";
    case IPMI_PRIVILEGE_OEM:
	return "oem";
    default:
	return "invalid";
    }
}

const char *
ipmi_channel_medium_string(int val)
{
    switch (val) {
    case IPMI_CHANNEL_MEDIUM_IPMB:
	return "IPMB";
    case IPMI_CHANNEL_MEDIUM_ICMB_V10:
	return "ICMB_V10";
    case IPMI_CHANNEL_MEDIUM_ICMB_V09:
	return "ICMB_V09";
    case IPMI_CHANNEL_MEDIUM_8023_LAN:
	return "8023_LAN";
    case IPMI_CHANNEL_MEDIUM_RS232:
	return "RS232";
    case IPMI_CHANNEL_MEDIUM_OTHER_LAN:
	return "OTHER_LAN";
    case IPMI_CHANNEL_MEDIUM_PCI_SMBUS:
	return "PCI_SMBUS";
    case IPMI_CHANNEL_MEDIUM_SMBUS_v1:
	return "SMBUS_v1";
    case IPMI_CHANNEL_MEDIUM_SMBUS_v2:
	return "SMBUS_v2";
    case IPMI_CHANNEL_MEDIUM_USB_v1:
	return "USB_v1";
    case IPMI_CHANNEL_MEDIUM_USB_v2:
	return "USB_v2";
    case IPMI_CHANNEL_MEDIUM_SYS_INTF:
	return "SYS_INTF";
    default:
	return "invalid";
    }
}

const char *
ipmi_channel_protocol_string(int val)
{
    switch (val) {
    case IPMI_CHANNEL_PROTOCOL_IPMB:
	return "IPMB";
    case IPMI_CHANNEL_PROTOCOL_ICMB:
	return "ICMB";
    case IPMI_CHANNEL_PROTOCOL_SMBus:
	return "SMBus";
    case IPMI_CHANNEL_PROTOCOL_KCS:
	return "KCS";
    case IPMI_CHANNEL_PROTOCOL_SMIC:
	return "SMIC";
    case IPMI_CHANNEL_PROTOCOL_BT_v10:
	return "BT_v10";
    case IPMI_CHANNEL_PROTOCOL_BT_v15:
	return "BT_v15";
    case IPMI_CHANNEL_PROTOCOL_TMODE:
	return "TMODE";
    default:
	return "invalid";
    }
}

const char *
ipmi_channel_session_support_string(int val)
{
    switch (val) {
    case IPMI_CHANNEL_SESSION_LESS:
	return "session-less";
    case IPMI_CHANNEL_SINGLE_SESSION:
	return "single-session";
    case IPMI_CHANNEL_MULTI_SESSION:
	return "multi-session";
    case IPMI_CHANNEL_SESSION_BASED:
	return "session-based";
    default:
	return "invalid";
    }
}

const char *
ipmi_channel_access_mode_string(int val)
{
    switch (val) {
    case IPMI_CHANNEL_ACCESS_MODE_DISABLED:
	return "DISABLED";
    case IPMI_CHANNEL_ACCESS_MODE_PRE_BOOT:
	return "PRE_BOOT";
    case IPMI_CHANNEL_ACCESS_MODE_ALWAYS:
	return "ALWAYS";
    case IPMI_CHANNEL_ACCESS_MODE_SHARED:
	return "SHARED";
    default:
	return "invalid";
    }
}
