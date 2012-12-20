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

/* Primarily to get string handling routines */
#include <OpenIPMI/ipmi_string.h>

#define MAX_SDR_LINE 256

struct sdr_field_name {
    char *name;
    unsigned int val;
};

struct sdr_field {
    char *name;
    enum { SDR_BITS, SDR_SBITS, SDR_MULTIBITS, SDR_MULTISBITS, SDR_MULTIBITS2,
	   SDR_STRING, SDR_BOOLBIT } type;
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

static struct sdr_field_name sensor_access_fields[] = {
    { "no", 0 }, { "readable", 1 }, { "settable", 2 }, { "fixed", 3 },
    { NULL }
};

static struct sdr_field_name sensor_event_msg_ctrl_fields[] = {
    { "per_state", 0 }, { "entire_sensor", 1 }, { "glbobal", 2 }, { "no", 3 },
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
    { "entity_id",		SDR_BITS,	 9, 0, 8, .required = 1 },
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
    { "sensor_type",		SDR_BITS,	13, 0, 8, .required = 1 },
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

    { "analog_data_format",	SDR_BITS,	21, 6, 2,
      .strvals = analog_data_format_fields },
    { "rate_unit",		SDR_BITS,	21, 3, 3,
      .strvals = rate_unit_fields },
    { "modifier_unit",		SDR_BITS,	21, 1, 2,
      .strvals = modifier_unit_fields },
    { "percentage",		SDR_BOOLBIT,	21, 0, 1 },
    { "base_unit",		SDR_BITS,	22, 0, 8 },
    { "modifier_unit",		SDR_BITS,	23, 0, 8 },
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
    { "r_exp",			SDR_BITS,	30, 4, 4 },
    { "b_exp",			SDR_BITS,	30, 0, 4 },
    { "normal_min_specified",	SDR_BOOLBIT,	31, 2, 1 },
    { "normal_max_specified",	SDR_BOOLBIT,	31, 1, 1 },
    { "nominal_specified",	SDR_BOOLBIT,	31, 0, 1 },
    { "nominal_reading",	SDR_BITS,	32, 0, 8 },
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
    { "entity_id",		SDR_BITS,	 9, 0, 8, .required = 1 },
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
    { "sensor_type",		SDR_BITS,	13, 0, 8, .required = 1 },
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
    { "entity_id",		SDR_BITS,	 9, 0, 8, .required = 1 },
    { "logical_entity",		SDR_BOOLBIT,	10, 7, 1 },
    { "entity_instance",	SDR_BITS,	10, 0, 8, .required = 1 },
    { "sensor_type",		SDR_BITS,	11, 0, 8, .required = 1 },
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
    { "container_entity_id",	SDR_BITS,	 6, 0, 8, .required = 1 },
    { "container_entity_inst",	SDR_BITS,	 7, 4, 4, .required = 1 },
    { "entities_are_range",	SDR_BOOLBIT,	 8, 7, 1 },
    { "linked_ears",		SDR_BOOLBIT,	 8, 6, 1 },
    { "presense_sensor_always_there",SDR_BOOLBIT, 8, 5, 1 },

    { "entity_1_id",		SDR_BITS,	 9, 0, 8, .required = 1 },
    { "entity_1_inst",		SDR_BITS,	 10, 0, 8, .required = 1 },
    { "entity_2_id",		SDR_BITS,	 11, 0, 8 },
    { "entity_2_inst",		SDR_BITS,	 12, 0, 8 },
    { "entity_3_id",		SDR_BITS,	 13, 0, 8 },
    { "entity_3_inst",		SDR_BITS,	 14, 0, 8 },
    { "entity_4_id",		SDR_BITS,	 15, 0, 8 },
    { "entity_4_inst",		SDR_BITS,	 16, 0, 8 },
};
#define TYPE8_LEN (sizeof(type8) / sizeof(struct sdr_field))

static struct sdr_field type9[] =
{
    { "container_entity_id",	SDR_BITS,	 6, 0, 8, .required = 1 },
    { "container_entity_inst",	SDR_BITS,	 7, 4, 4, .required = 1 },
    { "container_entity_dev_addr", SDR_BITS,	 8, 0, 8, .required = 1 },
    { "container_entity_dev_chan", SDR_BITS,	 9, 0, 8, .required = 1 },
    { "entities_are_range",	SDR_BOOLBIT,	 10, 7, 1 },
    { "linked_ears",		SDR_BOOLBIT,	 10, 6, 1 },
    { "presense_sensor_always_there",SDR_BOOLBIT, 10, 5, 1 },
    { "entity_1_dev_addr",	SDR_BITS,	 11, 0, 8, .required = 1 },
    { "entity_1_dev_chan",	SDR_BITS,	 12, 0, 8, .required = 1 },
    { "entity_1_id",		SDR_BITS,	 13, 0, 8, .required = 1 },
    { "entity_1_inst",		SDR_BITS,	 14, 0, 8, .required = 1 },
    { "entity_2_dev_addr",	SDR_BITS,	 15, 0, 8, .required = 1 },
    { "entity_2_dev_chan",	SDR_BITS,	 16, 0, 8, .required = 1 },
    { "entity_2_id",		SDR_BITS,	 17, 0, 8 },
    { "entity_2_inst",		SDR_BITS,	 18, 0, 8 },
    { "entity_3_dev_addr",	SDR_BITS,	 19, 0, 8, .required = 1 },
    { "entity_3_dev_chan",	SDR_BITS,	 20, 0, 8, .required = 1 },
    { "entity_3_id",		SDR_BITS,	 21, 0, 8 },
    { "entity_3_inst",		SDR_BITS,	 22, 0, 8 },
    { "entity_4_dev_addr",	SDR_BITS,	 23, 0, 8, .required = 1 },
    { "entity_4_dev_chan",	SDR_BITS,	 24, 0, 8, .required = 1 },
    { "entity_4_id",		SDR_BITS,	 25, 0, 8 },
    { "entity_4_inst",		SDR_BITS,	 26, 0, 8 },
};
#define TYPE9_LEN (sizeof(type9) / sizeof(struct sdr_field))

/*
 * To parse more complex expressions, we really need to know what the
 * save state is.  So we, unfortunately, have to create our own
 * version of strtok so we know what it is.
 */
char *
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
    return pos;
}

int
get_delim_str(char **rtokptr, char **rval, char **err)
{
    char *tokptr = *rtokptr;
    char endc;
    char *rv;

    while (isspace(*tokptr))
	tokptr++;
    if (*tokptr == '\0') {
	*err = "missing string value";
	return -1;
    }
    if (*tokptr != '"' && *tokptr != '\'') {
	*err = "string value must start with '\"' or '''";
	return -1;
    }
    endc = *tokptr;
    tokptr++;
    rv = tokptr;
    while (*tokptr != endc) {
	if (*tokptr == '\0') {
	    *err = "End of line in string";
	    return -1;
	}
	tokptr++;
    }
    *tokptr = '\0';
    *rtokptr = tokptr + 1;
    rv = strdup(rv);
    if (!rv) {
	*err = "Out of memory copying string";
	return -1;
    }
    *rval = rv;
    return 0;
}

int
get_bool(char **tokptr, unsigned int *rval, char **err)
{
    char *tok = mystrtok(NULL, " \t\n", tokptr);

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
get_uint(char **tokptr, unsigned int *rval, char **err)
{
    char *end;
    char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No integer value given";
	return -1;
    }

    *rval = strtoul(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }
    return 0;
}

int
get_int(char **tokptr, int *rval, char **err)
{
    char *end;
    char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No integer value given";
	return -1;
    }

    *rval = strtol(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }
    return 0;
}

static int
get_uint_str(struct sdr_field *t, char **tokptr, unsigned int *rval, char **err)
{
    char *end;
    char *tok = mystrtok(NULL, " \t\n", tokptr);

    if (t->strvals) {
	struct sdr_field_name *s = t->strvals;
	while (s->name) {
	    if (strcmp(s->name, tok) == 0) {
		*rval = s->val;
		return 0;
	    }
	}
    }
    *rval = strtol(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }
    return 0;
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

    if (type == 1) {
	t = type1;
	tlen = TYPE1_LEN;
	sdr_len = 48;
    } else if (type == 2) {
	t = type2;
	tlen = TYPE2_LEN;
	sdr_len = 32;
    } else if (type == 3) {
	t = type3;
	tlen = TYPE3_LEN;
	sdr_len = 17;
    } else if (type == 8) {
	t = type8;
	tlen = TYPE8_LEN;
	sdr_len = 16;
    } else if (type == 9) {
	t = type9;
	tlen = TYPE9_LEN;
	sdr_len = 32;
    } else {
	*errstr = "Unknown SDR type";
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
	char *tok;
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
		    err = store_sdr_bits(&t[j], sdr, sdr_len, uval, errstr);
		    if (err)
			goto out_err;
		    uval >>= t[i].bitsize;
		}
		break;
	    }

	    case SDR_STRING:
	    {
		unsigned char str[IPMI_MAX_STR_LEN];
		char *sval;
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
    sdr[4] = sdr_len;
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
    fprintf(stderr, "%s <input file>\n", progname);
    exit(1);
}

int
main(int argc, char *argv[])
{
    FILE *f;
    char *s, *tok, *tokptr;
    char buf[MAX_SDR_LINE];
    unsigned int line = 0;

    progname = argv[0];
    if (argc < 2) {
	fprintf(stderr, "No input file given\n");
	help();
    }

    f = fopen(argv[1], "r");
    if (!f) {
	fprintf(stderr, "Unable to open input file %s\n", argv[1]);
	exit(1);
    }

    while ((s = fgets(buf, sizeof(buf), f))) {
	int err;
	unsigned int sdrtype;
	char *errstr, *errstr2;
	unsigned char *sdr;
	unsigned int sdrlen;

	line++;
	tok = mystrtok(buf, " \t\n", &tokptr);
	if (!tok || (tok[0] == '#'))
	    continue;

	if (strcmp(tok, "sdr") != 0) {
	    fprintf(stderr, "%3d: Invalid input, expecting \"sdr type <n>\"\n",
		    line);
	    exit(1);
	}

	tok = mystrtok(NULL, " \n\t", &tokptr);
	if (!tok || strcmp(tok, "type") != 0) {
	    fprintf(stderr, "%3d: Invalid input, expecting \"sdr type <n>\"\n",
		    line);
	    exit(1);
	}

	err = get_uint(&tokptr, &sdrtype, &errstr);
	if (err) {
	    fprintf(stderr, "%3d: Invalid input, expecting \"sdr type <n>\": "
		    "%s\n", line, errstr);
	    exit(1);
	}

	if ((sdrtype > 3 && sdrtype < 8) || (sdrtype > 9)) {
	    fprintf(stderr, "%3d: Invalid sdr type, supported types are"
		    " 1, 2, 3, 8, and 9\n", line);
	    exit(1);
	}

	err = ipmi_compile_sdr(f, sdrtype, &sdr, &sdrlen, &errstr, &errstr2,
			       &line);
	if (err) {
	    if (errstr2)
		fprintf(stderr, "%3d: %s: %s\n", line, errstr, errstr2);
	    else
		fprintf(stderr, "%3d: %s\n", line, errstr);
	    exit(1);
	}
	fwrite(sdr, sdrlen, 1, stdout);
	free(sdr);
    }

    return 0;
}
