/*
 * strings.c
 *
 * MontaVista IPMI code for converting values to strings.
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

#include <stdlib.h>
#include <ipmi/ipmi_bits.h>

static char *hysteresis_support_types[] =
{
    "none",
    "readable",
    "settable",
    "fixed",
};
#define NUM_HYSTERESIS_SUPPORT_TYPES (sizeof(hysteresis_support_types)/sizeof(char *))
char *
ipmi_get_hysteresis_support_string(unsigned int val)
{
    if (val > NUM_HYSTERESIS_SUPPORT_TYPES)
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
char *
ipmi_get_threshold_access_support_string(unsigned int val)
{
    if (val > NUM_THRESHOLD_ACCESS_SUPPORT_TYPES)
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
char *
ipmi_get_event_support_string(unsigned int val)
{
    if (val > NUM_EVENT_SUPPORT_TYPES)
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
};
#define NUM_SENSOR_TYPES (sizeof(sensor_types)/sizeof(char *))
char *
ipmi_get_sensor_type_string(unsigned int val)
{
    if (val > NUM_SENSOR_TYPES)
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
char *
ipmi_get_event_reading_type_string(unsigned int val)
{
    if (val > NUM_EVENT_READING_TYPES)
	return "invalid";
    return event_reading_types[val];
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
char *
ipmi_get_rate_unit_string(unsigned int val)
{
    if (val > NUM_RATE_UNIT_TYPES)
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
    "uncorrectable_errors"
};
#define NUM_UNIT_TYPES (sizeof(unit_types)/sizeof(char *))
char *
ipmi_get_unit_type_string(unsigned int val)
{
    if (val > NUM_UNIT_TYPES)
	return "invalid";
    return unit_types[val];
}

static char *threshold_types[] =
{
    "lower non critical",
    "lower critical",
    "lower non recoverable",
    "upper non critical",
    "upper critical",
    "upper non recoverable"
};
#define NUM_THRESHOLD_TYPES (sizeof(threshold_types)/sizeof(char *))
char *
ipmi_get_threshold_string(unsigned int val)
{
    if (val > NUM_THRESHOLD_TYPES)
	return "invalid";
    return threshold_types[val];
}

static char *value_dir_types[] =
{
    "going low",
    "going high"
};
#define NUM_VALUE_DIR_TYPES (sizeof(value_dir_types)/sizeof(char *))
char *
ipmi_get_value_dir_string(unsigned int val)
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
char *
ipmi_get_event_dir_string(unsigned int val)
{
    if (val > NUM_EVENT_DIR_TYPES)
	return "invalid";
    return event_dir_types[val];
}

static char *entity_id_types[] =
{
    "unspecified",
    "other",
    "unkown",
    "processor",
    "disk",
    "peripheral",
    "system_management_module",
    "system_board",
    "memory_module",
    "processor_module",
    "power_supply",
    "add_in_card",
    "front_panel_board",
    "back_panel_board",
    "power_system_board",
    "drive_backplane",
    "system_internal_expansion_board",
    "other_system_board",
    "processor_board",
    "power_unit",
    "power_module",
    "power_management_board",
    "chassis_back_panel_board",
    "system_chassis",
    "sub_chassis",
    "other_chassis_board",
    "disk_drive_bay",
    "peripheral_bay",
    "device_bay",
    "fan_cooling",
    "cooling_unit",
    "cable_interconnect",
    "memory_device",
    "system_management_software",
    "bios",
    "operating_system",
    "system_bus",
    "group",
    "remote_mgmt_comm_device",
    "external_environment",
    "battery",
};
#define NUM_ENTITY_ID_TYPES (sizeof(entity_id_types)/sizeof(char *))
char *
ipmi_get_entity_id_string(unsigned int val)
{
    if (val > NUM_ENTITY_ID_TYPES)
	return "invalid";
    return entity_id_types[val];
}

static char *event_reading_states[256][15] =
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
      "transition to non-cricital from ok",
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

static char *sensor_states[256][15] =
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
	"Termal Trip",
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
    },
    {}, /* 0x0d */
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
    {}, /* 0x1b */
    {}, /* 0x1c */
    { /* 0x1d */
	"initiated by power up",
	"initiated by hard reset",
	"initiated by warm reset",
	"user requested PXE boot",
	"automatic boot to diagnostic"
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
	"run time stop"
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
    },
    { /* 0x29 */
	"battery low",
	"battery failed",
	"battery presence detected"
    },
};

char *
ipmi_get_reading_name(unsigned int event_reading_type,
		      unsigned int sensor_type,
		      unsigned int val)
{
    char *rv;
    if (event_reading_type == IPMI_EVENT_READING_TYPE_SENSOR_SPECIFIC) {
	if ((event_reading_type > 255) || (val > 15))
	    return "invalid";
	rv = sensor_states[event_reading_type][val];
    } else {
	if ((event_reading_type > 255) || (val > 15))
	    return "invalid";
	rv = event_reading_states[event_reading_type][val];
    }
    if (rv == NULL)
	return "unknown";
    return rv;
}
