
#include <stdio.h>
#include <stdint.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <malloc.h>

/* Primarily to get string handling routines */
#include <OpenIPMI/serv.h>
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
	return EINVAL;
    }

    sdr[t->pos] |= (bits & ((1 << t->bitsize) - 1)) << t->bitoff;
    return 0;
}

int
ipmi_compile_sdr(FILE *f, unsigned int type,
		 unsigned char **retbuf, unsigned int *retlen,
		 char **errstr, char **errstr2, unsigned int *errline)
{
    unsigned int i, j, tlen, line = 0;
    struct sdr_field *t;
    char *requireds;
    char buf[MAX_SDR_LINE];
    int err = EINVAL;
    char *tokptr;
    unsigned char *sdr = NULL;
    unsigned int sdr_len;

    *errstr2 = NULL;

    if (type == 1) {
	t = type1;
	tlen = TYPE1_LEN;
	sdr_len = 48;
    } else {
	*errstr = "Unknown SDR type";
	*errline = line;
	return EINVAL;
    }

    requireds = malloc(tlen * sizeof(char));
    if (!requireds) {
	*errstr = "Out of memory";
	*errline = line;
	return ENOMEM;
    }

    sdr = malloc(sdr_len);
    if (!sdr) {
	err = ENOMEM;
	*errstr = "Out of memory";
	goto out_err;
    }
    memset(sdr, 0, sdr_len);

    for (i = 0; i < tlen; i++)
	requireds[i] = t[i].required;

    for (;;) {
	char *tok;
	char *s = fgets(buf, sizeof(buf), f);
	if (s == NULL) {
	    err = EINVAL;
	    *errstr = "Unexpected end of file";
	    goto out_err;
	}

	line++;

	tok = mystrtok(buf, " \t\n", &tokptr);
	if (!tok || (tok[0] == '#'))
	    continue;

	if (strcmp(tok, "endsdr"))
	    break;

	for (i = 0; i < tlen; i++) {
	    if (strcmp(tok, t[i].name) == 0) {
		break;
	    }
	}
	if (i == tlen) {
	    err = EINVAL;
	    *errstr = "unknown SDR field";
	    goto out_err;
	}

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
		    err = EINVAL;
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
		    err = EINVAL;
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
			err = EINVAL;
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
			err = EINVAL;
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
		if (out_len >= 1) {
		    unsigned char *newsdr = realloc(sdr, sdr_len + out_len - 1);
		    if (!newsdr) {
			err = ENOMEM;
			*errstr = "Out of memory";
			goto out_err;
		    }
		    sdr = newsdr;
		}
		memcpy(sdr + t[i].pos, sdr, out_len);
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
	    err = EINVAL;
	    *errstr = "Missing required field:";
	    *errstr2 = t[i].name;
	    goto out_err;
	}
    }
    free(requireds);
    *retbuf = sdr;
    *retlen = sdr_len;
    return 0;

  out_err:
    free(requireds);
    if (sdr)
	free(sdr);
    *errline = line;
    return err;
}
