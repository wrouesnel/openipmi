
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include "emu.h"

typedef int (*ipmi_emu_cmd_handler)(emu_out_t  *out,
				    emu_data_t *emu,
				    lmc_data_t *mc,
				    char       **toks);

static int
emu_get_uchar(emu_out_t *out, char **toks, unsigned char *val, char *errstr,
	      int empty_ok)
{
    char *str, *tmpstr;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (empty_ok)
	    return ENOSPC;
	if (errstr)
	    out->printf(out, "**No %s given\n", errstr);
	return EINVAL;
    }
    if (str[0] == '\'') {
	*val = str[1];
	return 0;
    }
    *val = strtoul(str, &tmpstr, 16);
    if (*tmpstr != '\0') {
	if (errstr)
	    out->printf(out, "**Invalid %s given\n", errstr);
	return EINVAL;
    }

    return 0;
}

static int
emu_get_uchar_with_vals(emu_out_t *out, char **toks,
			unsigned char *val, char *errstr,
			int empty_ok, unsigned int numopts, ...)
{
    char *str, *tmpstr;
    va_list ap;
    unsigned int i;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (empty_ok)
	    return ENOSPC;
	if (errstr)
	    out->printf(out, "**No %s given\n", errstr);
	return EINVAL;
    }
    if (str[0] == '\'') {
	*val = str[1];
	return 0;
    }

    va_start(ap, numopts);
    for (i = 0; i < numopts; i++) {
	char *v = va_arg(ap, char *);
	unsigned char vval = va_arg(ap, unsigned int);
	if (strcmp(v, str) == 0) {
	    *val = vval;
	    va_end(ap);
	    goto out;
	}
    }
    va_end(ap);

    *val = strtoul(str, &tmpstr, 16);
    if (*tmpstr != '\0') {
	if (errstr)
	    out->printf(out, "**Invalid %s given\n", errstr);
	return EINVAL;
    }
 out:
    return 0;
}

static int
emu_get_bitmask(emu_out_t *out, char **toks, unsigned char *val, char *errstr,
		unsigned int size, int empty_ok)
{
    char *str;
    int  i, j;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (empty_ok)
	    return ENOSPC;
	if (errstr)
	    out->printf(out, "**No %s given\n", errstr);
	return EINVAL;
    }
    if (strlen(str) != size) {
	if (errstr)
	    out->printf(out, "**invalid number of bits in %s\n", errstr);
	return EINVAL;
    }
    for (i=size-1, j=0; i>=0; i--, j++) {
	if (str[j] == '0') {
	    val[i] = 0;
	} else if (str[j] == '1') {
	    val[i] = 1;
	} else {
	    if (errstr)
		out->printf(out, "**Invalid bit value '%c' in %s\n", str[j], errstr);
	    return EINVAL;
	}
    }

    return 0;
}

static int
emu_get_uint(emu_out_t *out, char **toks, unsigned int *val, char *errstr)
{
    char *str, *tmpstr;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (errstr)
	    out->printf(out, "**No %s given\n", errstr);
	return EINVAL;
    }
    *val = strtoul(str, &tmpstr, 16);
    if (*tmpstr != '\0') {
	if (errstr)
	    out->printf(out, "**Invalid %s given\n", errstr);
	return EINVAL;
    }

    return 0;
}

static int
emu_get_bytes(emu_out_t *out, char **tokptr, unsigned char *data, char *errstr,
	      unsigned int len)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);
    char *end;

    if (!tok) {
	if (errstr)
	    out->printf(out, "**No %s given\n", errstr);
	return EINVAL;
    }
    if (*tok == '"') {
	int end;
	/* Ascii PW */
	tok++;
	end = strlen(tok) - 1;
	if (tok[end] != '"') {
	  out->printf(out, "**ASCII %s doesn't end in '\"'", errstr);
	    return EINVAL;
	}
	tok[end] = '\0';
	strncpy((char *) data, tok, len);
	zero_extend_ascii(data, len);
    } else {
	unsigned int i;
	char         c[3];
	/* HEX pw */
	if (strlen(tok) != 32) {
	    out->printf(out, "**HEX %s not 32 HEX characters long", errstr);
	    return EINVAL;
	}
	c[2] = '\0';
	for (i=0; i<len; i++) {
	    c[0] = *tok;
	    tok++;
	    c[1] = *tok;
	    tok++;
	    data[i] = strtoul(c, &end, 16);
	    if (*end != '\0') {
		out->printf(out, "**Invalid HEX character in %s", errstr);
		return -1;
	    }
	}
    }

    return 0;
}

#define INPUT_BUFFER_SIZE 65536
int
read_command_file(emu_out_t *out, emu_data_t *emu, char *command_file)
{
    FILE *f = fopen(command_file, "r");
    int  rv;

    if (!f) {
	out->printf(out, "Unable to open command file '%s'\n", command_file);
    } else {
	char *buffer;
	int  pos = 0;

	buffer = malloc(INPUT_BUFFER_SIZE);
	if (!buffer) {
	    out->printf(out, "Could not allocate buffer memory\n");
	    goto out;
	}
	while (fgets(buffer+pos, INPUT_BUFFER_SIZE-pos, f)) {
	    out->printf(out, "%s", buffer+pos);
	    if (buffer[pos] == '#')
		continue;
	    pos = strlen(buffer);
	    if (pos == 0)
		continue;
	    pos--;
	    while ((pos > 0) && (buffer[pos] == '\n'))
		pos--;
	    if (pos == 0)
		continue;
	    if ((pos > 0) && (buffer[pos] == '\\')) {
		/* Continue the line. */
		/* Don't do pos--, write over the "\\" */
		continue;
	    }
	    pos++;
	    buffer[pos] = 0;
	    
	    rv = ipmi_emu_cmd(out, emu, buffer);
	    if (rv)
		return rv;
	    pos = 0;
	}
 out:
	if (buffer)
	    free(buffer);
	fclose(f);
    }

    return 0;
}

static int
sel_enable(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned int  max_records;
    unsigned char flags;

    rv = emu_get_uint(out, toks, &max_records, "max records");
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &flags, "flags", 0);
    if (rv)
	return rv;

    rv = ipmi_mc_enable_sel(mc, max_records, flags);
    if (rv)
	out->printf(out, "**Unable to enable sel, error 0x%x\n", rv);
    return rv;
}

static int
sel_add(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           i;
    int           rv;
    unsigned char record_type;
    unsigned char data[13];
    unsigned int  r;

    rv = emu_get_uchar(out, toks, &record_type, "record type", 0);
    if (rv)
	return rv;

    for (i=0; i<13; i++) {
	rv = emu_get_uchar(out, toks, &data[i], "data byte", 0);
	if (rv)
	    return rv;
    }

    rv = ipmi_mc_add_to_sel(mc, record_type, data, &r);
    if (rv)
	out->printf(out, "**Unable to add to sel, error 0x%x\n", rv);
    else
	out->printf(out, "Added record %d\n", r);
    return rv;
}

static int
main_sdr_add(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           i;
    int           rv;
    unsigned char data[256];

    for (i=0; i<256; i++) {
	rv = emu_get_uchar(out, toks, &data[i], "data byte", 1);
	if (rv == ENOSPC)
	    break;
	if (rv) {
	    out->printf(out, "**Error 0x%x in data byte %d\n", rv, i);
	    return rv;
	}
    }

    rv = ipmi_mc_add_main_sdr(mc, data, i);
    if (rv)
	out->printf(out, "**Unable to add to sdr, error 0x%x\n", rv);
    return rv;
}

static int
device_sdr_add(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           i;
    int           rv;
    unsigned char data[256];
    unsigned char lun;

    rv = emu_get_uchar(out, toks, &lun, "LUN", 0);
    if (rv)
	return rv;

    for (i=0; i<256; i++) {
	rv = emu_get_uchar(out, toks, &data[i], "data byte", 1);
	if (rv == ENOSPC)
	    break;
	if (rv) {
	    out->printf(out, "**Error 0x%x in data byte %d\n", rv, i);
	    return rv;
	}
    }

    rv = ipmi_mc_add_device_sdr(mc, lun, data, i);
    if (rv)
	out->printf(out, "**Unable to add to sdr, error 0x%x\n", rv);
    return rv;
}

static int
sensor_add(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned char lun;
    unsigned char num;
    unsigned char type;
    unsigned char code;
    char *tok;

    rv = emu_get_uchar(out, toks, &lun, "LUN", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &num, "sensor num", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &type, "sensor type", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &code, "event reading code", 0);
    if (rv)
	return rv;

    tok = mystrtok(NULL, " \t\n", toks);
    if (tok) {
	ipmi_sensor_handler_t *handler = ipmi_sensor_find_handler(tok);
	unsigned int poll_rate;
	void *rcb_data;
	char *errstr;

	if (!handler) {
	    out->printf(out, "**Invalid sensor handler: %s\n", tok);
	    return -1;
	}

	rv = emu_get_uint(out, toks, &poll_rate, "poll rate");
	if (rv)
	    return rv;

	rv = handler->init(mc, lun, num, toks, handler->cb_data, &rcb_data,
			   &errstr);
	if (rv) {
	    out->printf(out, "**Error initializing sensor handler: %s\n", 
			errstr);
	    return rv;
	}

	rv = ipmi_mc_add_polled_sensor(mc, lun, num, type, code,
				       poll_rate, handler->poll, rcb_data);
				       
    } else {
	rv = ipmi_mc_add_sensor(mc, lun, num, type, code);
    }
	if (rv)
	    out->printf(out, "**Unable to add to sensor, error 0x%x\n", rv);
    return rv;
}

static int
sensor_set_bit(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned char lun;
    unsigned char num;
    unsigned char bit;
    unsigned char value;
    unsigned char gen_event;

    rv = emu_get_uchar(out, toks, &lun, "LUN", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &num, "sensor num", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &bit, "bit to set", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &value, "bit value", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &gen_event, "generate event", 0);
    if (rv)
	return rv;

    rv = ipmi_mc_sensor_set_bit(mc, lun, num, bit, value, gen_event);
    if (rv)
	out->printf(out, "**Unable to set sensor bit, error 0x%x\n", rv);
    return rv;
}

static int
sensor_set_bit_clr_rest(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned char lun;
    unsigned char num;
    unsigned char bit;
    unsigned char gen_event;

    rv = emu_get_uchar(out, toks, &lun, "LUN", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &num, "sensor num", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &bit, "bit to set", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &gen_event, "generate event", 0);
    if (rv)
	return rv;

    rv = ipmi_mc_sensor_set_bit_clr_rest(mc, lun, num, bit, gen_event);
    if (rv)
	out->printf(out, "**Unable to set sensor bit, error 0x%x\n", rv);
    return rv;
}

static int
sensor_set_value(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned char lun;
    unsigned char num;
    unsigned char value;
    unsigned char gen_event;

    rv = emu_get_uchar(out, toks, &lun, "LUN", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &num, "sensor num", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &value, "value", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &gen_event, "generate event", 0);
    if (rv)
	return rv;

    rv = ipmi_mc_sensor_set_value(mc, lun, num, value, gen_event);
    if (rv)
	out->printf(out, "**Unable to set sensor value, error 0x%x\n", rv);
    return rv;
}

static int
sensor_set_hysteresis(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned char lun;
    unsigned char num;
    unsigned char support;
    unsigned char positive, negative;

    rv = emu_get_uchar(out, toks, &lun, "LUN", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &num, "sensor num", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar_with_vals(out, toks, &support, "hysteresis support", 0,
				 4,
				 "none", 0,
				 "readable", 1,
				 "settable", 2,
				 "fixed", 3);
    if (rv)
	return rv;

    printf("Hysteresis: %d\n", support);

    rv = emu_get_uchar(out, toks, &positive, "positive hysteresis", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &negative, "negative hysteresis", 0);
    if (rv)
	return rv;

    rv = ipmi_mc_sensor_set_hysteresis(mc, lun, num, support, positive,
				       negative);
    if (rv)
	out->printf(out, "**Unable to set sensor hysteresis, error 0x%x\n", rv);
    return rv;
}

static int
sensor_set_threshold(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned char lun;
    unsigned char num;
    unsigned char support;
    unsigned char enabled[6];
    unsigned char thresholds[6];
    int           i;

    rv = emu_get_uchar(out, toks, &lun, "LUN", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &num, "sensor num", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar_with_vals(out, toks, &support, "threshold support", 0,
				 4,
				 "none", 0,
				 "readable", 1,
				 "settable", 2,
				 "fixed", 3);
    if (rv)
	return rv;

    rv = emu_get_bitmask(out, toks, enabled, "threshold enabled", 6, 0);
    if (rv)
	return rv;

    for (i=5; i>=0; i--) {
	rv = emu_get_uchar(out, toks, &thresholds[i], "threshold value", 0);
	if (rv)
	    return rv;
    }

    rv = ipmi_mc_sensor_set_threshold(mc, lun, num, support,
				      enabled, thresholds);
    if (rv)
	out->printf(out, "**Unable to set sensor thresholds, error 0x%x\n", rv);
    return rv;
}

static int
sensor_set_event_support(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned char lun;
    unsigned char num;
    unsigned char support;
    unsigned char events_enable;
    unsigned char scanning;
    unsigned char assert_support[15];
    unsigned char deassert_support[15];
    unsigned char assert_enabled[15];
    unsigned char deassert_enabled[15];

    rv = emu_get_uchar(out, toks, &lun, "LUN", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &num, "sensor num", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar_with_vals(out, toks, &events_enable, "events enable", 0,
				 4,
				 "enable", 1,
				 "true", 1,
				 "disable", 0,
				 "false", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar_with_vals(out, toks, &scanning, "scanning", 0,
				 4,
				 "scanning", 1,
				 "true", 1,
				 "no-scanning", 0,
				 "false", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar_with_vals(out, toks, &support, "event support", 0,
				 4,
				 "per-state", 0,
				 "entire-sensor", 1,
				 "global", 2,
				 "none", 3);
    if (rv)
	return rv;

    rv = emu_get_bitmask(out, toks, assert_support, "assert support", 15, 0);
    if (rv)
	return rv;

    rv = emu_get_bitmask(out, toks, deassert_support, "deassert support", 15, 0);
    if (rv)
	return rv;

    rv = emu_get_bitmask(out, toks, assert_enabled, "assert enabled", 15, 0);
    if (rv)
	return rv;

    rv = emu_get_bitmask(out, toks, deassert_enabled, "deassert enabled", 15, 0);
    if (rv)
	return rv;

    rv = ipmi_mc_sensor_set_event_support(mc, lun, num,
					  events_enable, scanning,
					  support,
					  assert_support, deassert_support,
					  assert_enabled, deassert_enabled);
    if (rv)
	out->printf(out, "**Unable to set sensor thresholds, error 0x%x\n", rv);
    return rv;
}

static int
mc_add(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    unsigned char ipmb;
    unsigned char device_id;
    unsigned char has_device_sdrs;
    unsigned char device_revision;
    unsigned char major_fw_rev;
    unsigned char minor_fw_rev;
    unsigned char device_support;
    unsigned char mfg_id[3];
    unsigned int  mfg_id_i;
    unsigned char product_id[2];
    unsigned int  product_id_i;
    unsigned char dyn_sens = 0;
    int           rv;
    
    rv = emu_get_uchar(out, toks, &ipmb, "IPMB address", 0);
    if (rv)
	return rv;
    rv = emu_get_uchar(out, toks, &device_id, "Device ID", 0);
    if (rv)
	return rv;
    rv = emu_get_uchar_with_vals(out, toks, &has_device_sdrs,
				 "Has Device SDRs", 0,
				 2,
				 "has-device-sdrs", 1,
				 "no-device-sdrs", 0);
    if (rv)
	return rv;
    rv = emu_get_uchar(out, toks, &device_revision, "Device Revision", 0);
    if (rv)
	return rv;
    rv = emu_get_uchar(out, toks, &major_fw_rev, "Major FW Rev", 0);
    if (rv)
	return rv;
    rv = emu_get_uchar(out, toks, &minor_fw_rev, "Minor FW Rev", 0);
    if (rv)
	return rv;
    rv = emu_get_uchar(out, toks, &device_support, "Device Support", 0);
    if (rv)
	return rv;
    rv = emu_get_uint(out, toks, &mfg_id_i, "Manufacturer ID");
    if (rv)
	return rv;
    rv = emu_get_uint(out, toks, &product_id_i, "Product ID");
    if (rv)
	return rv;

    /* Don't care on an error */
    emu_get_uchar(out, toks, &dyn_sens, "Dynamic Sensor Population", 1);

    mfg_id[0] = mfg_id_i & 0xff;
    mfg_id[1] = (mfg_id_i >> 8) & 0xff;
    mfg_id[2] = (mfg_id_i >> 16) & 0xff;
    product_id[0] = product_id_i & 0xff;
    product_id[1] = (product_id_i >> 8) & 0xff;
    rv = ipmi_emu_add_mc(emu, ipmb, device_id, has_device_sdrs,
			 device_revision, major_fw_rev, minor_fw_rev,
			 device_support, mfg_id, product_id, dyn_sens);
    if (rv)
	out->printf(out, "**Unable to add the MC, error 0x%x\n", rv);
    return rv;
}

static int
mc_set_guid(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    unsigned char guid[16];
    int           rv;

    rv = emu_get_bytes(out, toks, guid, "GUID", 16);
    if (rv)
	return rv;

    rv = ipmi_emu_set_mc_guid(mc, guid, 1);

    return rv;
}

static int
mc_delete(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    ipmi_mc_destroy(mc);
    return 0;
}

static int
mc_disable(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    ipmi_mc_disable(mc);
    return 0;
}

static int
mc_enable(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    ipmi_mc_enable(mc);
    return 0;
}

static int
mc_set_power(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    unsigned char power;
    unsigned char gen_int;
    int           rv;

    rv = emu_get_uchar(out, toks, &power, "Power", 0);
    if (rv)
	return rv;

    rv = emu_get_uchar(out, toks, &gen_int, "Gen int", 0);
    if (rv)
	return rv;

    rv = ipmi_mc_set_power(mc, power, gen_int);
    if (rv)
	out->printf(out, "**Unable to set power, error 0x%x\n", rv);
    return rv;
}

#define MAX_FRU_SIZE 8192
static int
mc_add_fru_data(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    unsigned char data[MAX_FRU_SIZE];
    unsigned char devid;
    unsigned int  length;
    unsigned int  i;
    int           rv;

    rv = emu_get_uchar(out, toks, &devid, "Device ID", 0);
    if (rv)
	return rv;

    rv = emu_get_uint(out, toks, &length, "FRU physical size");
    if (rv)
	return rv;

    for (i=0; i<length; i++) {
	rv = emu_get_uchar(out, toks, &data[i], "data byte", 1);
	if (rv == ENOSPC)
	    break;
	if (rv) {
	    out->printf(out, "**Error 0x%x in data byte %d\n", rv, i);
	    return rv;
	}
    }

    rv = emu_get_uchar(out, toks, &data[i], "data byte", 1);
    if (rv != ENOSPC) {
	out->printf(out, "**Error: input data too long for FRU\n", rv, i);
	return EINVAL;
    }

    memset(data + i, 0, length - i);

    rv = ipmi_mc_add_fru_data(mc, devid, length, NULL, data);
    if (rv)
	out->printf(out, "**Unable to add FRU data, error 0x%x\n", rv);
    return rv;
}

static int
mc_dump_fru_data(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    unsigned char *data = NULL;
    unsigned char devid;
    unsigned int  length;
    unsigned int  i;
    int           rv;

    rv = emu_get_uchar(out, toks, &devid, "Device ID", 0);
    if (rv)
	return rv;

    rv = ipmi_mc_get_fru_data_len(mc, devid, &length);
    if (rv) {
	out->printf(out, "**Unable to dump FRU data, error 0x%x\n", rv);
	goto out;
    }

    data = malloc(length);
    if (!data) {
	out->printf(out, "**Unable to dump FRU data, out of memory\n", rv);
	goto out;
    }

    rv = ipmi_mc_get_fru_data(mc, devid, length, data);
    if (rv) {
	out->printf(out, "**Unable to dump FRU data, error 0x%x\n", rv);
	goto out;
    }

    for (i=0; i<length; i++) {
	if ((i > 0) && ((i % 8) == 0))
	    out->printf(out, "\n");
	out->printf(out, " 0x%2.2x", data[i]);
    }
    out->printf(out, "\n");

 out:
    if (data)
	free(data);
    return rv;
}

static int
mc_setbmc(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    unsigned char ipmb;
    int           rv;

    rv = emu_get_uchar(out, toks, &ipmb, "IPMB address of BMC", 0);
    if (rv)
	return rv;
    rv = ipmi_emu_set_bmc_mc(emu, ipmb);
    if (rv)
	out->printf(out, "**Invalid IPMB address\n");
    return rv;
}

static int
atca_enable(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int rv;

    rv = ipmi_emu_atca_enable(emu);
    if (rv)
	out->printf(out, "**Unable to enable ATCA mode, error 0x%x\n", rv);
    return rv;
}

static int
atca_set_site(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned char hw_address;
    unsigned char site_type;
    unsigned char site_number;
    
    rv = emu_get_uchar(out, toks, &hw_address, "hardware address", 0);
    if (rv)
	return rv;
    rv = emu_get_uchar(out, toks, &site_type, "site type", 0);
    if (rv)
	return rv;
    rv = emu_get_uchar(out, toks, &site_number, "site number", 0);
    if (rv)
	return rv;

    rv = ipmi_emu_atca_set_site(emu, hw_address, site_type, site_number);
    if (rv)
	out->printf(out, "**Unable to set site type, error 0x%x\n", rv);
    return rv;
}

static int
mc_set_num_leds(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned char count;

    rv = emu_get_uchar(out, toks, &count, "number of LEDs", 0);
    if (rv)
	return rv;

    rv = ipmi_mc_set_num_leds(mc, count);
    if (rv)
	out->printf(out, "**Unable to set number of LEDs, error 0x%x\n", rv);
    return rv;
}

static int
read_cmds(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    char *filename = strtok_r(NULL, " \t\n", toks);

    if (!filename) {
	out->printf(out, "**No filename specified\n");
	return EINVAL;
    }

    return read_command_file(out, emu, filename);
}

static int
sleep_cmd(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    unsigned int   time;
    struct timeval tv;
    int            rv;

    rv = emu_get_uint(out, toks, &time, "timeout");
    if (rv)
	return rv;

    tv.tv_sec = time / 1000;
    tv.tv_usec = (time % 1000) * 1000;
    ipmi_emu_sleep(emu, &tv);
    return 0;
}

static int
debug_cmd(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    unsigned int   level = 0;
    char           *tok;

    while ((tok = strtok_r(NULL, " \t\n", toks))) {
	if (strcmp(tok, "raw") == 0) {
	    level |= DEBUG_RAW_MSG;
	} else if (strcmp(tok, "msg") == 0) {
	    level |= DEBUG_MSG;
	} else {
	    out->printf(out, "Invalid debug level '%s', options are 'raw' and 'msg'\n",
		   tok);
	    return EINVAL;
	}
    }
    
    emu_set_debug_level(emu, level);
    return 0;
}

static int
quit(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    fflush(stdout);
    ipmi_emu_shutdown(emu);
    return 0;
}

#define MC	1
#define NOMC	0
static struct {
    char                 *name;
    int                  flags;
    ipmi_emu_cmd_handler handler;
} cmds[] =
{
    { "quit",		NOMC,		quit },
    { "sel_enable",	MC,		sel_enable },
    { "sel_add",	MC,		sel_add },
    { "main_sdr_add",	MC,		main_sdr_add },
    { "device_sdr_add",	MC,		device_sdr_add },
    { "sensor_add",     MC,             sensor_add },
    { "sensor_set_bit", MC,             sensor_set_bit },
    { "sensor_set_bit_clr_rest", MC,        sensor_set_bit_clr_rest },
    { "sensor_set_value", MC,           sensor_set_value },
    { "sensor_set_hysteresis", MC,      sensor_set_hysteresis },
    { "sensor_set_threshold", MC,       sensor_set_threshold },
    { "sensor_set_event_support", MC,   sensor_set_event_support },
    { "mc_set_power",   MC,		mc_set_power },
    { "mc_add_fru_data",MC,		mc_add_fru_data },
    { "mc_dump_fru_data",MC,		mc_dump_fru_data },
    { "mc_set_num_leds",MC,		mc_set_num_leds },
    { "mc_add",		NOMC,		mc_add },
    { "mc_delete",	MC,		mc_delete },
    { "mc_disable",	MC,		mc_disable },
    { "mc_enable",	MC,		mc_enable },
    { "mc_setbmc",      NOMC,		mc_setbmc },
    { "mc_set_guid",	MC,		mc_set_guid },
    { "atca_enable",    NOMC,	        atca_enable },
    { "atca_set_site",	NOMC,		atca_set_site },
    { "read_cmds",	NOMC,		read_cmds },
    { "sleep",		NOMC,		sleep_cmd },
    { "debug",		NOMC,		debug_cmd },
    { NULL }
};

int
ipmi_emu_cmd(emu_out_t *out, emu_data_t *emu, char *cmd_str)
{
    char       *toks;
    char       *cmd;
    int        i;
    int        rv = EINVAL;
    lmc_data_t *mc = NULL;

    cmd = strtok_r(cmd_str, " \t\n", &toks);
    if (!cmd)
	return 0;
    if (cmd[0] == '#')
	return 0;

    for (i=0; cmds[i].name; i++) {
	if (strcmp(cmd, cmds[i].name) == 0) {
	    if (cmds[i].flags & MC) {
		unsigned char ipmb;
		rv = emu_get_uchar(out, &toks, &ipmb, "MC address", 0);
		if (rv)
		    return rv;
		rv = ipmi_emu_get_mc_by_addr(emu, ipmb, &mc);
		if (rv) {
		    out->printf(out, "**Invalid MC address\n");
		    return rv;
		}
	    }
	    rv = cmds[i].handler(out, emu, mc, &toks);
	    if (rv)
		return rv;
	    goto out;
	}
    }

    out->printf(out, "**Unknown command: %s\n", cmd);

 out:
    return rv;
}
