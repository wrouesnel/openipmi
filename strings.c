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

static char *hysteresis_support_types[] =
{
    "none",
    "readable",
    "settable",
    "fixed",
};
#define NUM_HYSTERESIS_SUPPORT_TYPES (sizeof(hysteresis_support_types)/sizeof(char *))
char *
get_hysteresis_support_string(unsigned int val)
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
get_threshold_access_support_string(unsigned int val)
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
get_event_support_string(unsigned int val)
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
get_sensor_type_string(unsigned int val)
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
get_event_reading_type_string(unsigned int val)
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
get_rate_unit_string(unsigned int val)
{
    if (val > NUM_RATE_UNIT_TYPES)
	return "invalid";
    return rate_unit_types[val];
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
get_threshold_string(unsigned int val)
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
get_value_dir_string(unsigned int val)
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
get_event_dir_string(unsigned int val)
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
get_entity_id_string(unsigned int val)
{
    if (val > NUM_ENTITY_ID_TYPES)
	return "invalid";
    return entity_id_types[val];
}

