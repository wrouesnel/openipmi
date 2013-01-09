/*
 * sdrcomp.c
 *
 * MontaVista IPMI SDR compiler
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2012 MontaVista Software Inc.
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
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.  */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <malloc.h>
#include <math.h>
#include <time.h>

/* Primarily to get string handling routines */
#include <OpenIPMI/ipmi_string.h>

#include "persist.c"

#define MAX_SDR_LINE 256

struct sdr_field_name {
    char *name;
    unsigned int val;
};

struct sdr_field {
    char *name;
    enum { SDR_BITS, SDR_SBITS, SDR_MULTIBITS, SDR_MULTISBITS, SDR_MULTIBITS2,
	   SDR_STRING, SDR_BOOLBIT, SDR_THRESH } type;
    /*
     * IMPORTANT: pos is offset + 1, the values given in the IPMI spec.
     * It is not zero-based.
     */
    uint16_t pos;
    uint8_t  bitoff;
    uint8_t  bitsize;
    uint8_t  required;
    uint16_t default_val;
    struct sdr_field_name *strvals;
};

static struct sdr_field_name entity_id_fields[] = {
    { "unspecified", 0 },
    { "other", 1 },
    { "unknown", 2 },
    { "processor", 3 },
    { "disk_or_disk_bay", 4 },
    { "peripheral_bay", 5 },
    { "system_management_module", 6 },
    { "system_board", 7 },
    { "memory_module", 8 },
    { "processor_module", 9 },
    { "power_supply", 10 },
    { "add-in_card", 11 },
    { "front_panel_board", 12 },
    { "back_panel_board", 13 },
    { "power_system_board", 14 },
    { "drive_backplane", 15 },
    { "system_internal_expansion_board", 16 },
    { "other_system_board", 17 },
    { "processor_board", 18 },
    { "power_unit", 19 },
    { "power_module", 20 },
    { "power_management", 21 },
    { "chassis_back_panel_board", 22 },
    { "system_chassis", 23 },
    { "sub-chassis", 24 },
    { "Other_chassis_board", 25 },
    { "Disk_Drive_Bay", 26 },
    { "Peripheral_Bay", 27 },
    { "Device_Bay", 28 },
    { "fan_cooling_device", 29 },
    { "cooling_unit", 30 },
    { "cable_interconnect", 31 },
    { "memory_device", 32 },
    { "system_management_software", 33  },
    { "bios", 34  },
    { "operating_system", 35  },
    { "system_bus", 36  },
    { "group", 37  },
    { "remote_management_communication_device", 38 },
    { "external_environment", 39 },
    { "battery", 40 },
    { "processing_blade", 41 },
    { "connectivity_switch", 42 },
    { "processor/memory_module", 43 },
    { "i/o_module", 44 },
    { "processor/_io_module", 45 },
    { "management_controller_firmware", 46 },
    { "ipmi_channel", 47 },
    { "pci_bus", 48 },
    { "pci_express_bus", 49 },
    { "scsi_bus", 50 },
    { "sata_/_sas_bus", 51 },
    { "processor_/_front-side_bus", 52 }
};

static struct sdr_field_name sensor_type_fields[] = {
    { "Temperature", 1 },
    { "Voltage", 2 },
    { "Current", 3 },
    { "Fan", 4 },
    { "Physical_Security", 5 },
    { "Platform_Security_Violation_Attempt", 6 },
    { "Processor", 7 },
    { "Power_Supply", 8 },
    { "Power_Unit", 9 },
    { "Cooling_Device", 10 },
    { "Other_Units_Based_Sensor", 11 },
    { "Memory", 12 },
    { "Drive_Slot", 13 },
    { "POST_Memory_Resize", 14 },
    { "System_Firmware_Progress", 15 },
    { "Event_Logging_Disabled", 16 },
    { "Watchdog_1", 17 },
    { "System_Event", 18 },
    { "Critical_Interrupt", 19 },
    { "Button_Switch", 20 },
    { "Module_Board", 21 },
    { "Microcontroller_Coprocessor", 22 },
    { "Add_In_Card", 23 },
    { "Chassis", 24 },
    { "Chip_Set", 25 },
    { "Other_Fru", 26 },
    { "Cable_Interconnect", 27 },
    { "Terminator", 28 },
    { "System_Boot_Initiated", 29 },
    { "Boot_Error", 30 },
    { "OS_Boot", 31 },
    { "OS_Critical_Stop", 32 },
    { "Slot_Connector", 33 },
    { "System_ACPI_Power_State", 34 },
    { "Watchdog_2", 35 },
    { "Platform_Alert", 36 },
    { "Entity_Presence", 37 },
    { "Monitor_ASIC_IC", 38 },
    { "LAN", 39 },
    { "Management_Subsystem_Health", 40 },
    { "Battery", 41 },
    { "Session_Audit", 42 },
    { "Version_Change", 43 },
    { "FRU_State", 44 }
};

static struct sdr_field_name sensor_access_fields[] = {
    { "no", 0 }, { "readable", 1 }, { "settable", 2 }, { "fixed", 3 },
    { NULL }
};

static struct sdr_field_name sensor_event_msg_ctrl_fields[] = {
    { "per_state", 0 }, { "entire_sensor", 1 }, { "global", 2 }, { "no", 3 },
    { NULL }
};


static struct sdr_field_name analog_data_format_fields[] = {
    { "unsigned", 0 }, { "1s_complement", 1 }, { "2s_complement", 2 },
    { "no", 3 },
    { NULL }
};

static struct sdr_field_name rate_unit_fields[] = {
    { "none", 0 }, { "per_us", 1 }, { "per_ms", 2 }, { "per_s", 3 },
    { "per_min", 4 }, { "per_hour", 5 }, { "per_day", 6 },
    { NULL }
};

static struct sdr_field_name modifier_unit_fields[] = {
    { "none", 0 }, { "multiply", 1 }, { "divide", 2 },
    { NULL }
};

static struct sdr_field_name base_unit_fields[] = {
    { "unspecified", 0 },
    { "degrees_C", 1 },
    { "degrees_F", 2 },
    { "degrees_K", 3 },
    { "Volts", 4 },
    { "Amps", 5 },
    { "Watts", 6 },
    { "Joules", 7 },
    { "Coulombs", 8 },
    { "VA", 9 },
    { "Nits", 10 },
    { "lumen", 11 },
    { "lux", 12 },
    { "Candela", 13 },
    { "kPa", 14 },
    { "PSI", 15 },
    { "Newton", 16 },
    { "CFM", 17 },
    { "RPM", 18 },
    { "Hz", 19 },
    { "microsecond", 20 },
    { "millisecond", 21 },
    { "second", 22 },
    { "minute", 23 },
    { "hour", 24 },
    { "day", 25 },
    { "week", 26 },
    { "mil", 27 },
    { "inches", 28 },
    { "feet", 29 },
    { "cu_in", 30 },
    { "cu_feet", 31 },
    { "mm", 32 },
    { "cm", 33 },
    { "m", 34 },
    { "cu_cm", 35 },
    { "cu_m", 36 },
    { "liters", 37 },
    { "fluid_ounce", 38 },
    { "radians", 39 },
    { "steradians", 40 },
    { "revolutions", 41 },
    { "cycles", 42 },
    { "gravities", 43 },
    { "ounce", 44 },
    { "pound", 45 },
    { "ft-lb", 46 },
    { "oz-in", 47 },
    { "gauss", 48 },
    { "gilberts", 49 },
    { "henry", 50 },
    { "millihenry", 51 },
    { "farad", 52 },
    { "microfarad", 53 },
    { "ohms", 54 },
    { "siemens", 55 },
    { "mole", 56 },
    { "becquerel", 57 },
    { "PPM", 58 },
    { "reserved", 59 },
    { "Decibels", 60 },
    { "DbA", 61 },
    { "DbC", 62 },
    { "gray", 63 },
    { "sievert", 64 },
    { "color_temp_deg_K", 65 },
    { "bit", 66 },
    { "kilobit", 67 },
    { "megabit", 68 },
    { "gigabit", 69 },
    { "byte", 70 },
    { "kilobyte", 71 },
    { "megabyte", 72 },
    { "gigabyte", 73 },
    { "word", 74 },
    { "dword", 75 },
    { "qword", 76 },
    { "line", 77 },
    { "hit", 78 },
    { "miss", 79 },
    { "retry", 80 },
    { "reset", 81 },
    { "overrun_overflow", 82 },
    { "underrun", 83 },
    { "collision", 84 },
    { "packets", 85 },
    { "messages", 86 },
    { "characters", 87 },
    { "error", 88 },
    { "correctable_error", 89 },
    { "uncorrectable_error", 90 }
};

static struct sdr_field_name linearization_fields[] = {
    { "linear", 0 }, { "ln", 1 },       { "log10", 2 },    { "log2", 3 },
    { "e", 4 },      { "exp10", 5 },    { "exp2", 6 },     { "1/x", 7 },
    { "sqr(x)", 9 }, { "cube(x)", 10 }, { "sqrt(x)", 11 }, { "cube-1(x)", 12 },
    { "non-linear", 0x70 },
    { NULL }
};

static struct sdr_field_name sensor_direction_fields[] = {
    { "n/a", 0 }, { "input", 1 }, { "output", 2 },
    { NULL }
};

static struct sdr_field type1[] =
{
    { "sensor_owner_id",	SDR_BITS,	 6, 0, 8, .required = 1 },
    { "channel_number",		SDR_BITS,	 7, 4, 4, .required = 1 },
    { "sensor_owner_lun",	SDR_BITS,	 7, 0, 2, .required = 1 },
    { "sensor_number",		SDR_BITS,	 8, 0, 8, .required = 1 },
    { "entity_id",		SDR_BITS,	 9, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "logical_entity",		SDR_BOOLBIT,	10, 7, 1 },
    { "entity_instance",	SDR_BITS,	10, 0, 8, .required = 1 },
    { "init_scanning",		SDR_BOOLBIT,	11, 6, 1 },
    { "init_events",		SDR_BOOLBIT,	11, 5, 1 },
    { "init_thresholds",	SDR_BOOLBIT,	11, 4, 1 },
    { "init_hysteresis",	SDR_BOOLBIT,	11, 3, 1 },
    { "init_sensor_type",	SDR_BOOLBIT,	11, 2, 1 },
    { "default_event_gen_on",	SDR_BOOLBIT,	11, 1, 1 },
    { "default_sensor_scan_on",	SDR_BOOLBIT,	11, 0, 1 },
    { "ignore_if_no_entity",	SDR_BOOLBIT,	12, 7, 1 },
    { "sensor_auto_rearm",	SDR_BOOLBIT,	12, 6, 1 },
    { "sensor_hysteresis",	SDR_BITS,	12, 4, 2,
      .strvals = sensor_access_fields },
    { "sensor_threshold_access",SDR_BITS,	12, 2, 2,
      .strvals = sensor_access_fields },
    { "sensor_event_msg_ctrl",	SDR_BITS,	12, 0, 2,
      .strvals = sensor_event_msg_ctrl_fields },
    { "sensor_type",		SDR_BITS,	13, 0, 8, .required = 1,
      .strvals = sensor_type_fields },
    { "event_reading_type_code",SDR_BITS,	14, 0, 8, .required = 1 },

    { "assert_event14",		SDR_BOOLBIT,	16, 6, 1 },
    { "assert_event13",		SDR_BOOLBIT,	16, 5, 1 },
    { "assert_event12",		SDR_BOOLBIT,	16, 4, 1 },
    { "assert_event11",		SDR_BOOLBIT,	16, 3, 1 },
    { "assert_event10",		SDR_BOOLBIT,	16, 2, 1 },
    { "assert_event9",		SDR_BOOLBIT,	16, 1, 1 },
    { "assert_event8",		SDR_BOOLBIT,	16, 0, 1 },
    { "assert_event7",		SDR_BOOLBIT,	15, 7, 1 },
    { "assert_event6",		SDR_BOOLBIT,	15, 6, 1 },
    { "assert_event5",		SDR_BOOLBIT,	15, 5, 1 },
    { "assert_event4",		SDR_BOOLBIT,	15, 4, 1 },
    { "assert_event3",		SDR_BOOLBIT,	15, 3, 1 },
    { "assert_event2",		SDR_BOOLBIT,	15, 2, 1 },
    { "assert_event1",		SDR_BOOLBIT,	15, 1, 1 },
    { "assert_event0",		SDR_BOOLBIT,	15, 0, 1 },
    { "return_lnr",		SDR_BOOLBIT,	16, 6, 1 },
    { "return_lc",		SDR_BOOLBIT,	16, 5, 1 },
    { "return_lnc",		SDR_BOOLBIT,	16, 4, 1 },
    { "assert_unrgh",		SDR_BOOLBIT,	16, 3, 1 },
    { "assert_unrgl",		SDR_BOOLBIT,	16, 2, 1 },
    { "assert_ucgh",		SDR_BOOLBIT,	16, 1, 1 },
    { "assert_ucgl",		SDR_BOOLBIT,	16, 0, 1 },
    { "assert_uncgh",		SDR_BOOLBIT,	15, 7, 1 },
    { "assert_uncgl",		SDR_BOOLBIT,	15, 6, 1 },
    { "assert_lnrgh",		SDR_BOOLBIT,	15, 5, 1 },
    { "assert_lnrgl",		SDR_BOOLBIT,	15, 4, 1 },
    { "assert_lcgh",		SDR_BOOLBIT,	15, 3, 1 },
    { "assert_lcgl",		SDR_BOOLBIT,	15, 2, 1 },
    { "assert_lncgh",		SDR_BOOLBIT,	15, 1, 1 },
    { "assert_lncgl",		SDR_BOOLBIT,	15, 0, 1 },

    { "deassert_event14",	SDR_BOOLBIT,	18, 6, 1 },
    { "deassert_event13",	SDR_BOOLBIT,	18, 5, 1 },
    { "deassert_event12",	SDR_BOOLBIT,	18, 4, 1 },
    { "deassert_event11",	SDR_BOOLBIT,	18, 3, 1 },
    { "deassert_event10",	SDR_BOOLBIT,	18, 2, 1 },
    { "deassert_event9",	SDR_BOOLBIT,	18, 1, 1 },
    { "deassert_event8",	SDR_BOOLBIT,	18, 0, 1 },
    { "deassert_event7",	SDR_BOOLBIT,	17, 7, 1 },
    { "deassert_event6",	SDR_BOOLBIT,	17, 6, 1 },
    { "deassert_event5",	SDR_BOOLBIT,	17, 5, 1 },
    { "deassert_event4",	SDR_BOOLBIT,	17, 4, 1 },
    { "deassert_event3",	SDR_BOOLBIT,	17, 3, 1 },
    { "deassert_event2",	SDR_BOOLBIT,	17, 2, 1 },
    { "deassert_event1",	SDR_BOOLBIT,	17, 1, 1 },
    { "deassert_event0",	SDR_BOOLBIT,	17, 0, 1 },
    { "return_unr",		SDR_BOOLBIT,	18, 6, 1 },
    { "return_uc",		SDR_BOOLBIT,	18, 5, 1 },
    { "return_unc",		SDR_BOOLBIT,	18, 4, 1 },
    { "deassert_unrgh",		SDR_BOOLBIT,	18, 3, 1 },
    { "deassert_unrgl",		SDR_BOOLBIT,	18, 2, 1 },
    { "deassert_ucgh",		SDR_BOOLBIT,	18, 1, 1 },
    { "deassert_ucgl",		SDR_BOOLBIT,	18, 0, 1 },
    { "deassert_uncgh",		SDR_BOOLBIT,	17, 7, 1 },
    { "deassert_uncgl",		SDR_BOOLBIT,	17, 6, 1 },
    { "deassert_lnrgh",		SDR_BOOLBIT,	17, 5, 1 },
    { "deassert_lnrgl",		SDR_BOOLBIT,	17, 4, 1 },
    { "deassert_lcgh",		SDR_BOOLBIT,	17, 3, 1 },
    { "deassert_lcgl",		SDR_BOOLBIT,	17, 2, 1 },
    { "deassert_lncgh",		SDR_BOOLBIT,	17, 1, 1 },
    { "deassert_lncgl",		SDR_BOOLBIT,	17, 0, 1 },

    { "event14_state_ret",	SDR_BOOLBIT,	20, 6, 1 },
    { "event13_state_ret",	SDR_BOOLBIT,	20, 5, 1 },
    { "event12_state_ret",	SDR_BOOLBIT,	20, 4, 1 },
    { "event11_state_ret",	SDR_BOOLBIT,	20, 3, 1 },
    { "event10_state_ret",	SDR_BOOLBIT,	20, 2, 1 },
    { "event9_state_ret",	SDR_BOOLBIT,	20, 1, 1 },
    { "event8_state_ret",	SDR_BOOLBIT,	20, 0, 1 },
    { "event7_state_ret",	SDR_BOOLBIT,	19, 7, 1 },
    { "event6_state_ret",	SDR_BOOLBIT,	19, 6, 1 },
    { "event5_state_ret",	SDR_BOOLBIT,	19, 5, 1 },
    { "event4_state_ret",	SDR_BOOLBIT,	19, 4, 1 },
    { "event3_state_ret",	SDR_BOOLBIT,	19, 3, 1 },
    { "event2_state_ret",	SDR_BOOLBIT,	19, 2, 1 },
    { "event1_state_ret",	SDR_BOOLBIT,	19, 1, 1 },
    { "event0_state_ret",	SDR_BOOLBIT,	19, 0, 1 },
    { "unr_thrsh_settable",	SDR_BOOLBIT,	20, 5, 1 },
    { "uc_thrsh_settable",	SDR_BOOLBIT,	20, 4, 1 },
    { "unc_thrsh_settable",	SDR_BOOLBIT,	20, 3, 1 },
    { "lnr_thresh_settable",	SDR_BOOLBIT,	20, 2, 1 },
    { "lc_thrsh_settable",	SDR_BOOLBIT,	20, 1, 1 },
    { "lnc_thrsh_settable",	SDR_BOOLBIT,	20, 0, 1 },
    { "unr_thrsh_readable",	SDR_BOOLBIT,	19, 5, 1 },
    { "uc_thrsh_readable",	SDR_BOOLBIT,	19, 4, 1 },
    { "unc_thrsh_readable",	SDR_BOOLBIT,	19, 3, 1 },
    { "lnr_thrsh_readable",	SDR_BOOLBIT,	19, 2, 1 },
    { "lc_thrsh_readable",	SDR_BOOLBIT,	19, 1, 1 },
    { "lnc_thrsh_readable",	SDR_BOOLBIT,	19, 0, 1 },

    { "analog_data_format",	SDR_BITS,	21, 6, 2,
      .strvals = analog_data_format_fields },
    { "rate_unit",		SDR_BITS,	21, 3, 3,
      .strvals = rate_unit_fields },
    { "modifier_unit",		SDR_BITS,	21, 1, 2,
      .strvals = modifier_unit_fields },
    { "percentage",		SDR_BOOLBIT,	21, 0, 1 },
    { "base_unit",		SDR_BITS,	22, 0, 8,
      .strvals = base_unit_fields },
    { "modifier_unit_code",	SDR_BITS,	23, 0, 8,
      .strvals = base_unit_fields },
    { "linearization",		SDR_BITS,	24, 0, 7,
      .strvals = linearization_fields },
    { "m",			SDR_MULTISBITS,	25, 0, 8 },
    { "m",			SDR_MULTIBITS2,	26, 6, 2 },
    { "tolerance",		SDR_BITS,	26, 0, 6 },
    { "b",			SDR_MULTISBITS,	27, 0, 8 },
    { "b",			SDR_MULTIBITS2,	28, 6, 2 },
    { "accuracy",		SDR_MULTISBITS,	28, 0, 6 },
    { "accuracy",		SDR_MULTIBITS2,	29, 4, 4 },
    { "accuracy_exp",		SDR_BITS,	29, 2, 2 },
    { "sensor_direction",	SDR_BITS,	29, 0, 2,
      .strvals = sensor_direction_fields },
    { "r_exp",			SDR_SBITS,	30, 4, 4 },
    { "b_exp",			SDR_SBITS,	30, 0, 4 },
    { "normal_min_specified",	SDR_BOOLBIT,	31, 2, 1 },
    { "normal_max_specified",	SDR_BOOLBIT,	31, 1, 1 },
    { "nominal_specified",	SDR_BOOLBIT,	31, 0, 1 },
    { "nominal_reading",	SDR_BITS,	32, 0, 8 },
    { "nominal_freading",	SDR_THRESH,	32, 0, 8 },
    { "normal_maximum",		SDR_BITS,	33, 0, 8 },
    { "normal_minimum",		SDR_BITS,	34, 0, 8 },
    { "sensor_maximum",		SDR_BITS,	35, 0, 8 },
    { "sensor_minimum",		SDR_BITS,	36, 0, 8 },
    { "unr_thresh",		SDR_BITS,	37, 0, 8 },
    { "uc_thresh",		SDR_BITS,	38, 0, 8 },
    { "unc_thresh",		SDR_BITS,	39, 0, 8 },
    { "lnr_thresh",		SDR_BITS,	40, 0, 8 },
    { "lc_thresh",		SDR_BITS,	41, 0, 8 },
    { "lnc_thresh",		SDR_BITS,	42, 0, 8 },
    { "unr_fthresh",		SDR_THRESH,	37, 0, 8 },
    { "uc_fthresh",		SDR_THRESH,	38, 0, 8 },
    { "unc_fthresh",		SDR_THRESH,	39, 0, 8 },
    { "lnr_fthresh",		SDR_THRESH,	40, 0, 8 },
    { "lc_fthresh",		SDR_THRESH,	41, 0, 8 },
    { "lnc_fthresh",		SDR_THRESH,	42, 0, 8 },
    { "positive_hysteresis",	SDR_BITS,	43, 0, 8 },
    { "negative_hysteresis",	SDR_BITS,	44, 0, 8 },
    { "oem",			SDR_BITS,	47, 0, 8 },
    { "id_string",		SDR_STRING,	48, 0, 8, .required = 1 },
};
#define TYPE1_LEN (sizeof(type1) / sizeof(struct sdr_field))

static struct sdr_field_name id_string_modifier_fields[] = {
    { "numeric", 0 }, { "alpha", 1 },
    { NULL }
};

static struct sdr_field type2[] =
{
    { "sensor_owner_id",	SDR_BITS,	 6, 0, 8, .required = 1 },
    { "channel_number",		SDR_BITS,	 7, 4, 4, .required = 1 },
    { "sensor_owner_lun",	SDR_BITS,	 7, 0, 2, .required = 1 },
    { "sensor_number",		SDR_BITS,	 8, 0, 8, .required = 1 },
    { "entity_id",		SDR_BITS,	 9, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "logical_entity",		SDR_BOOLBIT,	10, 7, 1 },
    { "entity_instance",	SDR_BITS,	10, 0, 8, .required = 1 },
    { "init_scanning",		SDR_BOOLBIT,	11, 6, 1 },
    { "init_events",		SDR_BOOLBIT,	11, 5, 1 },
    { "init_thresholds",	SDR_BOOLBIT,	11, 4, 1 },
    { "init_systeresis",	SDR_BOOLBIT,	11, 3, 1 },
    { "init_sensor_type",	SDR_BOOLBIT,	11, 2, 1 },
    { "default_event_gen_on",	SDR_BOOLBIT,	11, 1, 1 },
    { "default_sensor_scan_on",	SDR_BOOLBIT,	11, 0, 1 },
    { "ignore_if_no_entity",	SDR_BOOLBIT,	12, 7, 1 },
    { "sensor_auto_rearm",	SDR_BOOLBIT,	12, 6, 1 },
    { "sensor_hysteresis",	SDR_BITS,	12, 4, 2,
      .strvals = sensor_access_fields },
    { "sensor_threshold_access",SDR_BITS,	12, 2, 2,
      .strvals = sensor_access_fields },
    { "sensor_event_msg_ctrl",	SDR_BITS,	12, 0, 2,
      .strvals = sensor_event_msg_ctrl_fields },
    { "sensor_type",		SDR_BITS,	13, 0, 8, .required = 1,
      .strvals = sensor_type_fields },
    { "event_reading_type_code",SDR_BITS,	14, 0, 8, .required = 1 },
    { "assert_event14",		SDR_BOOLBIT,	16, 6, 1 },
    { "assert_event13",		SDR_BOOLBIT,	16, 5, 1 },
    { "assert_event12",		SDR_BOOLBIT,	16, 4, 1 },
    { "assert_event11",		SDR_BOOLBIT,	16, 3, 1 },
    { "assert_event10",		SDR_BOOLBIT,	16, 2, 1 },
    { "assert_event9",		SDR_BOOLBIT,	16, 1, 1 },
    { "assert_event8",		SDR_BOOLBIT,	16, 0, 1 },
    { "assert_event7",		SDR_BOOLBIT,	15, 7, 1 },
    { "assert_event6",		SDR_BOOLBIT,	15, 6, 1 },
    { "assert_event5",		SDR_BOOLBIT,	15, 5, 1 },
    { "assert_event4",		SDR_BOOLBIT,	15, 4, 1 },
    { "assert_event3",		SDR_BOOLBIT,	15, 3, 1 },
    { "assert_event2",		SDR_BOOLBIT,	15, 2, 1 },
    { "assert_event1",		SDR_BOOLBIT,	15, 1, 1 },
    { "assert_event0",		SDR_BOOLBIT,	15, 0, 1 },
    { "assert_lnr",		SDR_BOOLBIT,	16, 6, 1 },
    { "assert_lc",		SDR_BOOLBIT,	16, 5, 1 },
    { "assert_lnc",		SDR_BOOLBIT,	16, 4, 1 },
    { "assert_unrgh",		SDR_BOOLBIT,	16, 3, 1 },
    { "assert_unrgl",		SDR_BOOLBIT,	16, 2, 1 },
    { "assert_ucgh",		SDR_BOOLBIT,	16, 1, 1 },
    { "assert_ucgl",		SDR_BOOLBIT,	16, 0, 1 },
    { "assert_uncgh",		SDR_BOOLBIT,	15, 7, 1 },
    { "assert_uncgl",		SDR_BOOLBIT,	15, 6, 1 },
    { "assert_lnrgh",		SDR_BOOLBIT,	15, 5, 1 },
    { "assert_lnrgl",		SDR_BOOLBIT,	15, 4, 1 },
    { "assert_lcgh",		SDR_BOOLBIT,	15, 3, 1 },
    { "assert_lcgl",		SDR_BOOLBIT,	15, 2, 1 },
    { "assert_lncgh",		SDR_BOOLBIT,	15, 1, 1 },
    { "assert_lncgl",		SDR_BOOLBIT,	15, 0, 1 },

    { "deassert_event14",	SDR_BOOLBIT,	18, 6, 1 },
    { "deassert_event13",	SDR_BOOLBIT,	18, 5, 1 },
    { "deassert_event12",	SDR_BOOLBIT,	18, 4, 1 },
    { "deassert_event11",	SDR_BOOLBIT,	18, 3, 1 },
    { "deassert_event10",	SDR_BOOLBIT,	18, 2, 1 },
    { "deassert_event9",	SDR_BOOLBIT,	18, 1, 1 },
    { "deassert_event8",	SDR_BOOLBIT,	18, 0, 1 },
    { "deassert_event7",	SDR_BOOLBIT,	17, 7, 1 },
    { "deassert_event6",	SDR_BOOLBIT,	17, 6, 1 },
    { "deassert_event5",	SDR_BOOLBIT,	17, 5, 1 },
    { "deassert_event4",	SDR_BOOLBIT,	17, 4, 1 },
    { "deassert_event3",	SDR_BOOLBIT,	17, 3, 1 },
    { "deassert_event2",	SDR_BOOLBIT,	17, 2, 1 },
    { "deassert_event1",	SDR_BOOLBIT,	17, 1, 1 },
    { "deassert_event0",	SDR_BOOLBIT,	17, 0, 1 },
    { "deassert_lnr",		SDR_BOOLBIT,	18, 6, 1 },
    { "deassert_lc",		SDR_BOOLBIT,	18, 5, 1 },
    { "deassert_lnc",		SDR_BOOLBIT,	18, 4, 1 },
    { "deassert_unrgh",		SDR_BOOLBIT,	18, 3, 1 },
    { "deassert_unrgl",		SDR_BOOLBIT,	18, 2, 1 },
    { "deassert_ucgh",		SDR_BOOLBIT,	18, 1, 1 },
    { "deassert_ucgl",		SDR_BOOLBIT,	18, 0, 1 },
    { "deassert_uncgh",		SDR_BOOLBIT,	17, 7, 1 },
    { "deassert_uncgl",		SDR_BOOLBIT,	17, 6, 1 },
    { "deassert_lnrgh",		SDR_BOOLBIT,	17, 5, 1 },
    { "deassert_lnrgl",		SDR_BOOLBIT,	17, 4, 1 },
    { "deassert_lcgh",		SDR_BOOLBIT,	17, 3, 1 },
    { "deassert_lcgl",		SDR_BOOLBIT,	17, 2, 1 },
    { "deassert_lncgh",		SDR_BOOLBIT,	17, 1, 1 },
    { "deassert_lncgl",		SDR_BOOLBIT,	17, 0, 1 },

    { "event14_state_ret",	SDR_BOOLBIT,	20, 6, 1 },
    { "event13_state_ret",	SDR_BOOLBIT,	20, 5, 1 },
    { "event12_state_ret",	SDR_BOOLBIT,	20, 4, 1 },
    { "event11_state_ret",	SDR_BOOLBIT,	20, 3, 1 },
    { "event10_state_ret",	SDR_BOOLBIT,	20, 2, 1 },
    { "event9_state_ret",	SDR_BOOLBIT,	20, 1, 1 },
    { "event8_state_ret",	SDR_BOOLBIT,	20, 0, 1 },
    { "event7_state_ret",	SDR_BOOLBIT,	19, 7, 1 },
    { "event6_state_ret",	SDR_BOOLBIT,	19, 6, 1 },
    { "event5_state_ret",	SDR_BOOLBIT,	19, 5, 1 },
    { "event4_state_ret",	SDR_BOOLBIT,	19, 4, 1 },
    { "event3_state_ret",	SDR_BOOLBIT,	19, 3, 1 },
    { "event2_state_ret",	SDR_BOOLBIT,	19, 2, 1 },
    { "event1_state_ret",	SDR_BOOLBIT,	19, 1, 1 },
    { "event0_state_ret",	SDR_BOOLBIT,	19, 0, 1 },
    { "unr_thrsh_settable",	SDR_BOOLBIT,	20, 5, 1 },
    { "uc_thrsh_settable",	SDR_BOOLBIT,	20, 4, 1 },
    { "unc_thrsh_settable",	SDR_BOOLBIT,	20, 3, 1 },
    { "lnr_thresh_settable",	SDR_BOOLBIT,	20, 2, 1 },
    { "lc_thrsh_settable",	SDR_BOOLBIT,	20, 1, 1 },
    { "lnc_thrsh_settable",	SDR_BOOLBIT,	20, 0, 1 },
    { "unr_thrsh_readable",	SDR_BOOLBIT,	19, 5, 1 },
    { "uc_thrsh_readable",	SDR_BOOLBIT,	19, 4, 1 },
    { "unc_thrsh_readable",	SDR_BOOLBIT,	19, 3, 1 },
    { "lnr_thrsh_readable",	SDR_BOOLBIT,	19, 2, 1 },
    { "lc_thrsh_readable",	SDR_BOOLBIT,	19, 1, 1 },
    { "lnc_thrsh_readable",	SDR_BOOLBIT,	19, 0, 1 },

    { "",			SDR_BITS,	21, 6, 2,
      .default_val = 3 },
    { "rate_unit",		SDR_BITS,	21, 3, 3,
      .strvals = rate_unit_fields },
    { "modifier_unit",		SDR_BITS,	21, 1, 2,
      .strvals = modifier_unit_fields },
    { "percentage",		SDR_BOOLBIT,	21, 0, 1 },
    { "base_unit",		SDR_BITS,	22, 0, 8 },
    { "modifier_unit",		SDR_BITS,	23, 0, 8 },
    { "sensor_direction",	SDR_BITS,	24, 6, 2,
      .strvals = sensor_direction_fields },
    { "id_string_modifier",	SDR_BITS,	24, 4, 2,
      .strvals = id_string_modifier_fields },
    { "share_count",		SDR_BITS,	24, 0, 4 },
    { "entity_instance_incr",	SDR_BOOLBIT,	25, 7, 1 },
    { "instance_modifier_off",	SDR_BITS,	25, 0, 7 },
    { "positive_hysteresis",	SDR_BITS,	26, 0, 8 },
    { "negative_hysteresis",	SDR_BITS,	27, 0, 8 },
    { "oem",			SDR_BITS,	31, 0, 8 },
    { "id_string",		SDR_STRING,	32, 0, 8, .required = 1 },
};
#define TYPE2_LEN (sizeof(type2) / sizeof(struct sdr_field))

static struct sdr_field type3[] =
{
    { "sensor_owner_id",	SDR_BITS,	 6, 0, 8, .required = 1 },
    { "channel_number",		SDR_BITS,	 7, 4, 4, .required = 1 },
    { "sensor_owner_lun",	SDR_BITS,	 7, 0, 2, .required = 1 },
    { "sensor_number",		SDR_BITS,	 8, 0, 8, .required = 1 },
    { "entity_id",		SDR_BITS,	 9, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "logical_entity",		SDR_BOOLBIT,	10, 7, 1 },
    { "entity_instance",	SDR_BITS,	10, 0, 8, .required = 1 },
    { "sensor_type",		SDR_BITS,	11, 0, 8, .required = 1,
      .strvals = sensor_type_fields },
    { "event_reading_type_code",SDR_BITS,	12, 0, 8, .required = 1 },
    { "sensor_direction",	SDR_BITS,	13, 6, 2,
      .strvals = sensor_direction_fields },
    { "id_string_modifier",	SDR_BITS,	13, 4, 2,
      .strvals = id_string_modifier_fields },
    { "share_count",		SDR_BITS,	13, 0, 4 },
    { "entity_instance_incr",	SDR_BOOLBIT,	14, 7, 1 },
    { "instance_modifier_off",	SDR_BITS,	14, 0, 7 },
    { "oem",			SDR_BITS,	16, 0, 8 },
    { "id_string",		SDR_STRING,	17, 0, 8, .required = 1 },
};
#define TYPE3_LEN (sizeof(type3) / sizeof(struct sdr_field))

static struct sdr_field type8[] =
{
    { "container_entity_id",	SDR_BITS,	 6, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "container_entity_inst",	SDR_BITS,	 7, 0, 8, .required = 1 },
    { "entities_are_range",	SDR_BOOLBIT,	 8, 7, 1 },
    { "linked_ears",		SDR_BOOLBIT,	 8, 6, 1 },
    { "presense_sensor_always_there",SDR_BOOLBIT, 8, 5, 1 },

    { "entity_1_id",		SDR_BITS,	 9, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "entity_1_inst",		SDR_BITS,	 10, 0, 8, .required = 1 },
    { "entity_2_id",		SDR_BITS,	 11, 0, 8,
      .strvals = entity_id_fields },
    { "entity_2_inst",		SDR_BITS,	 12, 0, 8 },
    { "entity_3_id",		SDR_BITS,	 13, 0, 8,
      .strvals = entity_id_fields },
    { "entity_3_inst",		SDR_BITS,	 14, 0, 8 },
    { "entity_4_id",		SDR_BITS,	 15, 0, 8,
      .strvals = entity_id_fields },
    { "entity_4_inst",		SDR_BITS,	 16, 0, 8 },
};
#define TYPE8_LEN (sizeof(type8) / sizeof(struct sdr_field))

static struct sdr_field type9[] =
{
    { "container_entity_id",	SDR_BITS,	 6, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "container_entity_inst",	SDR_BITS,	 7, 4, 4, .required = 1 },
    { "container_entity_dev_addr", SDR_BITS,	 8, 0, 8, .required = 1 },
    { "container_entity_dev_chan", SDR_BITS,	 9, 0, 8, .required = 1 },
    { "entities_are_range",	SDR_BOOLBIT,	 10, 7, 1 },
    { "linked_ears",		SDR_BOOLBIT,	 10, 6, 1 },
    { "presense_sensor_always_there",SDR_BOOLBIT, 10, 5, 1 },
    { "entity_1_dev_addr",	SDR_BITS,	 11, 0, 8, .required = 1 },
    { "entity_1_dev_chan",	SDR_BITS,	 12, 0, 8, .required = 1 },
    { "entity_1_id",		SDR_BITS,	 13, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "entity_1_inst",		SDR_BITS,	 14, 0, 8, .required = 1 },
    { "entity_2_dev_addr",	SDR_BITS,	 15, 0, 8 },
    { "entity_2_dev_chan",	SDR_BITS,	 16, 0, 8 },
    { "entity_2_id",		SDR_BITS,	 17, 0, 8,
      .strvals = entity_id_fields },
    { "entity_2_inst",		SDR_BITS,	 18, 0, 8 },
    { "entity_3_dev_addr",	SDR_BITS,	 19, 0, 8 },
    { "entity_3_dev_chan",	SDR_BITS,	 20, 0, 8 },
    { "entity_3_id",		SDR_BITS,	 21, 0, 8,
      .strvals = entity_id_fields },
    { "entity_3_inst",		SDR_BITS,	 22, 0, 8 },
    { "entity_4_dev_addr",	SDR_BITS,	 23, 0, 8 },
    { "entity_4_dev_chan",	SDR_BITS,	 24, 0, 8 },
    { "entity_4_id",		SDR_BITS,	 25, 0, 8,
      .strvals = entity_id_fields },
    { "entity_4_inst",		SDR_BITS,	 26, 0, 8 },
};
#define TYPE9_LEN (sizeof(type9) / sizeof(struct sdr_field))

static struct sdr_field type16[] =
{
    { "device_access_address",	SDR_BITS,	 6, 0, 8, .required = 1 },
    { "device_slave_address",	SDR_BITS,	 7, 0, 8, .required = 1 },
    { "channel_number",		SDR_BITS,	 8, 5, 3 },
    { "lun",			SDR_BITS,	 8, 3, 2 },
    { "private_bus_id",		SDR_BITS,	 8, 0, 3 },
    { "address_span",		SDR_BITS,	 9, 0, 3 },
    { "device_type",		SDR_BITS,	11, 0, 8, .required = 1 },
    { "device_type_modifier",	SDR_BITS,	12, 0, 8, .required = 1 },
    { "entity_id",		SDR_BITS,	13, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "entity_instance",	SDR_BITS,	14, 0, 8, .required = 1 },
    { "oem",			SDR_BITS,	15, 0, 8 },
    { "id_string",		SDR_STRING,	16, 0, 8, .required = 1 },
};
#define TYPE16_LEN (sizeof(type16) / sizeof(struct sdr_field))

static struct sdr_field type17[] =
{
    { "device_access_address",	SDR_BITS,	 6, 0, 8, .required = 1 },
    { "fru_device_address",	SDR_BITS,	 7, 0, 8, .required = 1 },
    { "logical_fru",		SDR_BOOLBIT,	 8, 7, 1 },
    { "lun",			SDR_BITS,	 8, 3, 2 },
    { "private_bus_id",		SDR_BITS,	 8, 0, 3 },
    { "channel_number",		SDR_BITS,	 9, 4, 4 },
    { "device_type",		SDR_BITS,	11, 0, 8, .required = 1 },
    { "device_type_modifier",	SDR_BITS,	12, 0, 8, .required = 1 },
    { "fru_entity_id",		SDR_BITS,	13, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "fru_entity_instance",	SDR_BITS,	14, 0, 8, .required = 1 },
    { "oem",			SDR_BITS,	15, 0, 8 },
    { "id_string",		SDR_STRING,	16, 0, 8, .required = 1 },
};
#define TYPE17_LEN (sizeof(type17) / sizeof(struct sdr_field))

static struct sdr_field_name gen_events_modifier_fields[] = {
    { "enable_event_msg_gen", 0 },
    { "disable_event_msg_gen", 1 },
    { "do_not_init", 2 },
    { NULL }
};

static struct sdr_field type18[] =
{
    { "device_slave_address",	SDR_BITS,	 6, 0, 8, .required = 1 },
    { "device_channel_number",	SDR_BITS,	 7, 0, 4, .required = 1 },
    { "ACPI_sys_power_state",	SDR_BOOLBIT,	 8, 7, 1 },
    { "ACPI_dev_power_state",	SDR_BOOLBIT,	 8, 6, 1 },
    { "static_controller",	SDR_BOOLBIT,	 8, 5, 1 },
    { "controller_logs_init",	SDR_BOOLBIT,	 8, 3, 1 },
    { "log_init",		SDR_BOOLBIT,	 8, 2, 1 },
    { "gen_events",		SDR_BITS,	 8, 0, 2,
      .strvals = gen_events_modifier_fields },
    { "chassis",		SDR_BOOLBIT,	 9, 7, 1 },
    { "bridge",			SDR_BOOLBIT,	 9, 6, 1 },
    { "ipmb_event_gen",		SDR_BOOLBIT,	 9, 5, 1 },
    { "ipmb_event_recv",	SDR_BOOLBIT,	 9, 4, 1 },
    { "fru_inventory",		SDR_BOOLBIT,	 9, 3, 1 },
    { "sel",			SDR_BOOLBIT,	 9, 2, 1 },
    { "sdr",			SDR_BOOLBIT,	 9, 1, 1 },
    { "sensor",			SDR_BOOLBIT,	 9, 0, 1 },
    { "entity_id",		SDR_BITS,	13, 0, 8, .required = 1,
      .strvals = entity_id_fields },
    { "entity_instance",	SDR_BITS,	14, 0, 8, .required = 1 },
    { "oem",			SDR_BITS,	15, 0, 8 },
    { "id_string",		SDR_STRING,	16, 0, 8, .required = 1 },
};
#define TYPE18_LEN (sizeof(type18) / sizeof(struct sdr_field))

struct variable {
    char *name;
    char *value;
    struct variable *next;
} *vars;

int
add_variable(const char *name, const char *value)
{
    struct variable *var = vars, *last = NULL;

    while (var) {
	if (strcmp(name, var->name) == 0)
	    break;
	last = var;
	var = var->next;
    }
    if (var) {
	free(var->value);
    } else {
	var = malloc(sizeof(*var));
	if (!var) {
	    fprintf(stderr, "Out of memory\n");
	    return ENOMEM;
	}
	var->name = strdup(name);
	if (!var->name) {
	    fprintf(stderr, "Out of memory\n");
	    return ENOMEM;
	}
	var->next = NULL;
	if (last)
	    last->next = var;
	else
	    vars = var;
    }
    
    var->value = strdup(value);
    if (!var->value) {
	fprintf(stderr, "Out of memory\n");
	return ENOMEM;
    }

    return 0;
}

const char
*find_var(const char *name)
{
    struct variable *var = vars;
    while (var) {
	if (strcmp(name, var->name) == 0)
	    break;
	var = var->next;
    }
    if (!var) {
	fprintf(stderr, "Unknown variable named %s\n", name);
	return NULL;
    }
    return var->value;
}

/*
 * To parse more complex expressions, we really need to know what the
 * save state is.  So we, unfortunately, have to create our own
 * version of strtok so we know what it is.
 */
const char *
mystrtok(char *str, const char *delim, char **next)
{
    char *pos;
    char *curr;

    if (str)
	curr = str;
    else
	curr = *next;

    /* Skip initial delimiters. */
    for (;;) {
	const char *c = delim;
	if (*curr == '\0') {
	    *next = curr;
	    return NULL;
	}

	while (*c != '\0') {
	    if (*c == *curr)
		break;
	    c++;
	}
	if (*c == '\0')
	    break;
	curr++;
    }

    pos = curr;
    /* Now collect until there is a delimiter. */
    for (;;) {
	const char *c = delim;
	if (*curr == '\0') {
	    *next = curr;
	    goto out;
	}
	while (*c != '\0') {
	    if (*c == *curr) {
		*curr = '\0';
		*next = curr + 1;
		goto out;
	    }
	    c++;
	}
	curr++;
    }
 out:
    if (*pos == '$')
	return find_var(pos + 1);
    else
	return pos;
}

int
isquote(char c)
{
    return c == '\'' || c == '"';
}

int
get_delim_str(char **rtokptr, const char **rval, char **err)
{
    char *tokptr = *rtokptr;
    char endc;
    char *rv = NULL;

    while (isspace(*tokptr))
	tokptr++;
    if (*tokptr == '\0') {
	*err = "missing string value";
	return -1;
    }
    for (;;) {
	const char *val;

	if (*tokptr == '$') {
	    char oldc;

	    tokptr++;
	    val = tokptr;
	    while (*tokptr && *tokptr != '$' &&
		   !isspace(*tokptr) && !isquote(*tokptr)) {
		tokptr++;
	    }
	    oldc = *tokptr;
	    *tokptr = '\0';
	    val = find_var(val);
	    if (!val)
		return -1;
	    *tokptr = oldc;
	} else if (isquote(*tokptr)) {
	    endc = *tokptr;
	    tokptr++;
	    val = tokptr;
	    while (*tokptr != endc) {
		if (*tokptr == '\0') {
		    *err = "End of line in string";
		    return -1;
		}
		tokptr++;
	    }
	    *tokptr = '\0';
	    tokptr++;
	} else {
	    *err = "string value must start with '\"' or '''";
	    return -1;
	}

	if (rv) {
	    char *newrv = malloc(strlen(rv) + strlen(val) + 1);
	    if (!newrv) {
		*err = "Out of memory copying string";
		return -1;
	    }
	    strcpy(newrv, rv);
	    strcat(newrv, val);
	    free(rv);
	    rv = newrv;
	} else {
	    rv = strdup(val);
	    if (!rv) {
		*err = "Out of memory copying string";
		return -1;
	    }
	}

	if (*tokptr == '\0' || isspace(*tokptr))
	    break;
    }
    *rtokptr = tokptr;
    *rval = rv;
    return 0;
}

int
get_bool(char **tokptr, unsigned int *rval, char **err)
{
    const char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No boolean value given";
	return -1;
    }
    if (strcasecmp(tok, "true") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "false") == 0)
	*rval = 0;
    else if (strcasecmp(tok, "on") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "off") == 0)
	*rval = 0;
    else if (strcasecmp(tok, "yes") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "no") == 0)
	*rval = 0;
    else if (strcasecmp(tok, "1") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "0") == 0)
	*rval = 0;
    else {
	*err = "Invalid boolean value, must be 'true', 'on', 'false', or 'off'";
	return -1;
    }

    return 0;
}

int
get_uint(char **tokptr, unsigned int *rval, char **err, const char *start)
{
    char *end;
    const char *tok;

    if (start)
	tok = start;
    else {
	tok = mystrtok(NULL, " \t\n", tokptr);
	if (!tok) {
	    *err = "No integer value given";
	    return -1;
	}
    }

    *rval = strtoul(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }

    tok = mystrtok(NULL, " \t\n", tokptr);
    if (tok) {
	const char *tok2 = mystrtok(NULL, " \t\n", tokptr);
	unsigned int val2;

	if (!tok2) {
	    *err = "No value after operator";
	    return -1;
	}
	val2 = strtoul(tok2, &end, 0);
	if (*end != '\0') {
	    *err = "Invalid integer value";
	    return -1;
	}

	if (strlen(tok) > 1) {
	    *err = "Invalid operator";
	    return -1;
	}
	switch (*tok) {
	case '+':
	    *rval += val2;
	    break;

	case '-':
	    *rval -= val2;
	    break;

	default:
	    *err = "Invalid operator";
	    return -1;
	}
    }
    return 0;
}

int
get_int(char **tokptr, int *rval, char **err)
{
    char *end;
    const char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No integer value given";
	return -1;
    }

    *rval = strtol(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }

    tok = mystrtok(NULL, " \t\n", tokptr);
    if (tok) {
	const char *tok2 = mystrtok(NULL, " \t\n", tokptr);
	int val2;

	if (!tok2) {
	    *err = "No value after operator";
	    return -1;
	}
	val2 = strtol(tok2, &end, 0);
	if (*end != '\0') {
	    *err = "Invalid integer value";
	    return -1;
	}

	if (strlen(tok) > 1) {
	    *err = "Invalid operator";
	    return -1;
	}
	switch (*tok) {
	case '+':
	    *rval += val2;
	    break;

	case '-':
	    *rval -= val2;
	    break;

	default:
	    *err = "Invalid operator";
	    return -1;
	}
    }
    return 0;
}

int
get_float(char **tokptr, double *rval, char **err)
{
    char *end;
    const char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No floating point value given";
	return -1;
    }

    *rval = strtod(tok, &end);
    if (*end != '\0') {
	*err = "Invalid floating point value";
	return -1;
    }
    return 0;
}

static int
get_uint_str(struct sdr_field *t, char **tokptr, unsigned int *rval, char **err)
{
    const char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (t->strvals) {
	struct sdr_field_name *s = t->strvals;
	while (s->name) {
	    if (strcmp(s->name, tok) == 0) {
		*rval = s->val;
		return 0;
	    }
	    s++;
	}
    }
    return get_uint(tokptr, rval, err, tok);
}

static int
store_sdr_bits(struct sdr_field *t, unsigned char *sdr, unsigned int len,
	       unsigned int bits, char **errstr)
{
    if (t->pos > len) {
	*errstr = "Internal error: position out of range";
	return -1;
    }

    sdr[t->pos - 1] |= (bits & ((1 << t->bitsize) - 1)) << t->bitoff;
    return 0;
}

static unsigned int
get_sdr_bits(unsigned char *sdr, unsigned int pos, unsigned int bitoff,
	     unsigned int len)
{
    return (sdr[pos - 1] >> bitoff) & ((1 << len) - 1);
}

int
ipmi_compile_sdr(FILE *f, unsigned int type,
		 unsigned char **retbuf, unsigned int *retlen,
		 char **errstr, char **errstr2, unsigned int *line)
{
    unsigned int i, j, tlen;
    struct sdr_field *t;
    char *requireds, *sets;
    char buf[MAX_SDR_LINE];
    int err = -1;
    char *tokptr;
    unsigned char *sdr = NULL;
    unsigned int sdr_len;

    *errstr2 = NULL;

    switch (type) {
    case 1:
	t = type1;
	tlen = TYPE1_LEN;
	sdr_len = 48;
	break;

    case 2:
	t = type2;
	tlen = TYPE2_LEN;
	sdr_len = 32;
	break;

    case 3:
	t = type3;
	tlen = TYPE3_LEN;
	sdr_len = 17;
	break;

    case 8:
	t = type8;
	tlen = TYPE8_LEN;
	sdr_len = 16;
	break;

    case 9:
	t = type9;
	tlen = TYPE9_LEN;
	sdr_len = 32;
	break;

    case 16:
	t = type16;
	tlen = TYPE16_LEN;
	sdr_len = 16;
	break;

    case 17:
	t = type17;
	tlen = TYPE17_LEN;
	sdr_len = 16;
	break;

    case 18:
	t = type18;
	tlen = TYPE18_LEN;
	sdr_len = 16;
	break;

    default:
	*errstr = "Unknown SDR type, supported types are 1, 2, 3, 8, 9,"
	    " 16 (0x10) and 17 (0x11)";
	return -1;
    }

    requireds = malloc(tlen * sizeof(char));
    if (!requireds) {
	*errstr = "Out of memory";
	return -1;
    }

    sets = malloc(tlen * sizeof(char));
    if (!sets) {
	free(requireds);
	*errstr = "Out of memory";
	return -1;
    }

    sdr = malloc(sdr_len);
    if (!sdr) {
	err = -1;
	*errstr = "Out of memory";
	goto out_err;
    }
    memset(sdr, 0, sdr_len);

    for (i = 0; i < tlen; i++) {
	requireds[i] = t[i].required;
	sets[i] = 0;
	if (t[i].default_val)
	    store_sdr_bits(&t[i], sdr, sdr_len, t[i].default_val, errstr);
    }

    for (;;) {
	const char *tok;
	char *s = fgets(buf, sizeof(buf), f);
	if (s == NULL) {
	    err = -1;
	    *errstr = "Unexpected end of file";
	    goto out_err;
	}

	(*line)++;

	tok = mystrtok(buf, " \t\n", &tokptr);
	if (!tok || (tok[0] == '#'))
	    continue;

	if (strcmp(tok, "endsdr") == 0)
	    break;

	for (i = 0; i < tlen; i++) {
	    if (strcmp(tok, t[i].name) == 0) {
		break;
	    }
	}
	if (i == tlen) {
	    err = -1;
	    *errstr = "unknown SDR field";
	    goto out_err;
	}

	if (sets[i]) {
	    err = -1;
	    *errstr = "Field already set in this SDR";
	    *errstr2 = t[i].name;
	    goto out_err;
	}
	sets[i] = 1;
	requireds[i] = 0;

	switch (t[i].type) {
	    case SDR_BITS:
	    {
		unsigned int uval, umax;

		err = get_uint_str(&t[i], &tokptr, &uval, errstr);
		if (err)
		    goto out_err;
		umax = 1 << t[i].bitsize;
		if (uval > umax) {
		    err = -1;
		    *errstr = "Value too large for bit size";
		    goto out_err;
		}
		err = store_sdr_bits(&t[i], sdr, sdr_len, uval, errstr);
		if (err)
		    goto out_err;
		break;
	    }

	    case SDR_SBITS:
	    {
		int sval, smin, smax;
		
		err = get_int(&tokptr, &sval, errstr);
		if (err)
		    goto out_err;
		smax = 1 << (t[i].bitsize - 1);
		smin = -smax - 1;
		if (sval > smax || sval < smin) {
		    err = -1;
		    *errstr = "Value out of range for bit size";
		    goto out_err;
		}
		err = store_sdr_bits(&t[i], sdr, sdr_len,
				     (unsigned int) sval, errstr);
		if (err)
		    goto out_err;
		break;
	    }

	    case SDR_BOOLBIT:
	    {
		unsigned int uval;

		err = get_bool(&tokptr, &uval, errstr);
		if (err)
		    goto out_err;
		err = store_sdr_bits(&t[i], sdr, sdr_len, uval, errstr);
		if (err)
		    goto out_err;
		break;
	    }

	    case SDR_MULTIBITS:
	    case SDR_MULTISBITS:
	    {
		unsigned int uval, totalbits;
		
		totalbits = t[i].bitsize;
		for (j = i + 1; t[j].type == SDR_MULTIBITS2; j++)
		    totalbits += t[j].bitsize;
		if (t[i].type == SDR_MULTISBITS) {
		    int sval, smin, smax;

		    err = get_int(&tokptr, &sval, errstr);
		    if (err)
			goto out_err;
		    smax = 1 << (totalbits - 1);
		    smin = -smax - 1;
		    if (sval > smax || sval < smin) {
			err = -1;
			*errstr = "Value out of range for bit size";
			goto out_err;
		    }
		    uval = (unsigned int) sval;
		} else {
		    unsigned int umax;

		    err = get_uint_str(&t[i], &tokptr, &uval, errstr);
		    if (err)
			goto out_err;
		    umax = 1 << totalbits;
		    if (uval > umax) {
			err = -1;
			*errstr = "Value too large for bit size";
			goto out_err;
		    }
		}
		err = store_sdr_bits(&t[i], sdr, sdr_len, uval, errstr);
		if (err)
		    goto out_err;
		for (j = i + 1; t[j].type == SDR_MULTIBITS2; j++) {
		    uval >>= t[j - 1].bitsize;
		    err = store_sdr_bits(&t[j], sdr, sdr_len, uval, errstr);
		    if (err)
			goto out_err;
		}
		break;
	    }

	    case SDR_STRING:
	    {
		unsigned char str[IPMI_MAX_STR_LEN];
		const char *sval;
		unsigned int out_len = sizeof(str);

		err = get_delim_str(&tokptr, &sval, errstr);
		if (err)
		    goto out_err;
		ipmi_set_device_string(sval, IPMI_ASCII_STR, strlen(sval),
				       str, 0, &out_len);
		if (out_len > 1) {
		    unsigned char *newsdr = realloc(sdr, sdr_len + out_len - 1);
		    if (!newsdr) {
			err = -1;
			*errstr = "Out of memory";
			goto out_err;
		    }
		    sdr = newsdr;
		    sdr_len += out_len - 1;
		}
		memcpy(sdr + t[i].pos - 1, str, out_len);
		break;
	    }

	    case SDR_MULTIBITS2:
		/* Should never happen */
		*errstr = "Internal error: multibits2 showed up";
		goto out_err;
		break;

	    case SDR_THRESH:
	    {
		double fval, fx;
		int m, b, r_exp, b_exp;

		err = get_float(&tokptr, &fval, errstr);
		if (err)
		    goto out_err;

		m = get_sdr_bits(sdr, 25, 0, 8);
		m |= get_sdr_bits(sdr, 26, 6, 2) << 8;
		if (m & (1 << 9))
		    m |= (~0 << 10);
		b = get_sdr_bits(sdr, 27, 0, 8);
		b |= get_sdr_bits(sdr, 28, 6, 2) << 8;
		if (b & (1 << 9))
		    b |= (~0 << 10);
		r_exp = get_sdr_bits(sdr, 30, 4, 4);
		if (r_exp & (1 << 3))
		    r_exp |= (~0 << 4);
		b_exp = get_sdr_bits(sdr, 30, 0, 4);
		if (b_exp & (1 << 3))
		    b_exp |= (~0 << 4);

		fx = (((fval / pow(10, r_exp)) - ((double) b) * pow(10, b_exp))
		      / ((double) m));

		if (t[i].name[0] == 'u')
		    fx = ceil(fx);
		else if (t[i].name[0] != 'l')
		    fx += .5; /* round */

		if (fx < 0.0 || fx > 255.0) {
		    err = -1;
		    *errstr = "Value out of range type";
		    goto out_err;
		}
		err = store_sdr_bits(&t[i], sdr, sdr_len,
				     (unsigned int) fx, errstr);
		if (err)
		    goto out_err;
		break;
	    }
	}
    }

    for (i = 0; i < tlen; i++) {
	if (requireds[i]) {
	    err = -1;
	    *errstr = "Missing required field:";
	    *errstr2 = t[i].name;
	    goto out_err;
	}
    }
    free(requireds);
    free(sets);
    sdr[2] = 0x51;
    sdr[3] = type;
    sdr[4] = sdr_len - 5;
    *retbuf = sdr;
    *retlen = sdr_len;
    return 0;

  out_err:
    free(requireds);
    free(sets);
    if (sdr)
	free(sdr);
    return err;
}

static char *progname;

static void help(void)
{
    fprintf(stderr, "%s [-r] <input file>\n", progname);
    exit(1);
}

static void
parse_file(const char *filename, FILE *f, persist_t *p, int outraw,
	   unsigned int *sdrnum)
{
    char buf[MAX_SDR_LINE];
    char *s;
    unsigned int line = 0;

    while ((s = fgets(buf, sizeof(buf), f))) {
	int err;
	unsigned int sdrtype;
	char *errstr, *errstr2;
	unsigned char *sdr;
	unsigned int sdrlen;
	char *tokptr;
	const char *tok;

	line++;
	tok = mystrtok(buf, " \t\n", &tokptr);
	if (!tok || (tok[0] == '#'))
	    continue;

	if (strcmp(tok, "sdr") == 0) {
	    tok = mystrtok(NULL, " \n\t", &tokptr);
	    if (!tok || strcmp(tok, "type") != 0) {
		fprintf(stderr,
			"%s:%3d: Invalid input, expecting \"sdr type <n>\"\n",
			filename, line);
		exit(1);
	    }

	    err = get_uint(&tokptr, &sdrtype, &errstr, NULL);
	    if (err) {
		fprintf(stderr,
			"%s:%3d: Invalid input, expecting \"sdr type <n>\":"
			" %s\n",
			filename, line, errstr);
		exit(1);
	    }

	    err = ipmi_compile_sdr(f, sdrtype, &sdr, &sdrlen, &errstr, &errstr2,
				   &line);
	    if (err) {
		if (errstr2)
		    fprintf(stderr, "%s:%3d: %s: %s\n", filename, line,
			    errstr, errstr2);
		else
		    fprintf(stderr, "%s:%3d: %s\n", filename, line, errstr);
		exit(1);
	    }

	    sdr[0] = *sdrnum & 0xff;
	    sdr[1] = (*sdrnum >> 8) & 0xff;

	    if (outraw) {
		fwrite(sdr, sdrlen, 1, stdout);
	    } else {
		err = add_persist_data(p, sdr, sdrlen, "%d", *sdrnum);
		if (err) {
		    fprintf(stderr, "Out of memory\n");
		    exit(1);
		}
	    }
	    (*sdrnum)++;
	    free(sdr);
	} else if (strcmp(tok, "define") == 0) {
	    const char *name;
	    const char *value;
	    name = mystrtok(NULL, " \n\t", &tokptr);
	    if (!name) {
		fprintf(stderr,
			"%s:%3d: Invalid input, expecting variable name\n",
			filename, line);
		exit(1);
	    }

	    err = get_delim_str(&tokptr, &value, &errstr);
	    if (err) {
		fprintf(stderr,
			"%s:%3d: Invalid value, expecting quote delimited"
			" string: %s\n", filename, line, errstr);
		exit(1);
	    }
	    
	    err = add_variable(name, value);
	    if (err)
		exit(1);
	} else if (strcmp(tok, "include") == 0) {
	    const char *nfilename;
	    FILE *f2;

	    err = get_delim_str(&tokptr, &nfilename, &errstr);
	    if (err) {
		fprintf(stderr,
			"%s:%3d: Invalid filename, expecting quote delimited"
			" string: %s\n", filename, line, errstr);
		exit(1);
	    }

	    f2 = fopen(nfilename, "r");
	    if (!f2) {
		fprintf(stderr, "%s:%3d: Unable to open included file %s\n",
			filename, line, nfilename);
		exit(1);
	    }

	    parse_file(nfilename, f2, p, outraw, sdrnum);
	    
	    fclose(f2);
	} else {
	    fprintf(stderr, "%s:%3d: Invalid input,"
		    " expecting \"sdr type <n>\"\n",
		    filename, line);
	    exit(1);
	}
    }

}

int
main(int argc, char *argv[])
{
    FILE *f;
    persist_t *p = NULL;
    unsigned int sdrnum = 1;
    int argn;
    int outraw = 0;

    progname = argv[0];

    for (argn = 1; argn < argc; argn++) {
	if (argv[argn][0] != '-')
	    break;
	if (strcmp(argv[argn], "--") == 0)
	    break;
	if (strcmp(argv[argn], "-r") == 0) {
	    outraw = 1;
	} else {
	    fprintf(stderr, "Invalid option: %s\n", argv[argn]);
	    exit(1);
	}
    }

    if ((argc - argn) < 1) {
	fprintf(stderr, "No input file given\n");
	help();
    }

    f = fopen(argv[1], "r");
    if (!f) {
	fprintf(stderr, "Unable to open input file %s\n", argv[1]);
	exit(1);
    }

    if (!outraw) {
	p = alloc_persist("");
	if (!p) {
	    fprintf(stderr, "Out of memory\n");
	    exit(1);
	}
    }

    parse_file(argv[1], f, p, outraw, &sdrnum);

    fclose(f);

    if (!outraw) {
	add_persist_int(p, time(NULL), "last_add_time");
	write_persist_file(p, stdout);
	free_persist(p);
    }

    return 0;
}
