
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <OpenIPMI/serv.h>
#include "emu.h"
#include <OpenIPMI/persist.h>

#define BASE_CONF_STR SYSCONFDIR "/ipmi"

static int
emu_get_uchar(emu_out_t *out, char **toks, unsigned char *val, char *errstr,
	      int empty_ok)
{
    const char *str;
    char *tmpstr;

    str = mystrtok(NULL, " \t\n", toks);
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
    *val = strtoul(str, &tmpstr, 0);
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
    const char *str;
    char *tmpstr;
    va_list ap;
    unsigned int i;

    str = mystrtok(NULL, " \t\n", toks);
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

    *val = strtoul(str, &tmpstr, 0);
    if (*tmpstr != '\0') {
	if (errstr)
	    out->printf(out, "**Invalid %s given\n", errstr);
	return EINVAL;
    }
 out:
    return 0;
}

static int
emu_get_bitmask(emu_out_t *out, char **toks, uint16_t *val, char *errstr,
		unsigned int size, int empty_ok)
{
    const char *str;
    int  i, j;

    str = mystrtok(NULL, " \t\n", toks);
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
    *val = 0;
    for (i=size-1, j=0; i>=0; i--, j++) {
	if (str[j] == '0') {
	    /* Nothing to do */
	} else if (str[j] == '1') {
	    *val |= 1 << i;
	} else {
	    if (errstr)
		out->printf(out, "**Invalid bit value '%c' in %s\n", str[j],
			    errstr);
	    return EINVAL;
	}
    }

    return 0;
}

static int
emu_get_uint(emu_out_t *out, char **toks, unsigned int *val, char *errstr)
{
    const char *str;
    char *tmpstr;

    str = mystrtok(NULL, " \t\n", toks);
    if (!str) {
	if (errstr)
	    out->printf(out, "**No %s given\n", errstr);
	return EINVAL;
    }
    *val = strtoul(str, &tmpstr, 0);
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
    const char *tok = mystrtok(NULL, " \t\n", tokptr);
    char *end;

    if (!tok) {
	if (errstr)
	    out->printf(out, "**No %s given\n", errstr);
	return EINVAL;
    }
    if (*tok == '"') {
	unsigned int end;
	/* Ascii PW */
	tok++;
	end = strlen(tok) - 1;
	if (tok[end] != '"') {
	  out->printf(out, "**ASCII %s doesn't end in '\"'", errstr);
	    return EINVAL;
	}
	if (end > (len - 1))
	    end = len - 1;
	memcpy(data, tok, end);
	data[end] = '\0';
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
read_command_file(emu_out_t *out, emu_data_t *emu, const char *command_file)
{
    FILE *f = fopen(command_file, "r");
    int  rv = 0;

    if (!f) {
	rv = ENOENT;
    } else {
	char *buffer;
	int  pos = 0;

	buffer = malloc(INPUT_BUFFER_SIZE);
	if (!buffer) {
	    out->printf(out, "Could not allocate buffer memory\n");
	    rv = ENOMEM;
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
		break;
	    pos = 0;
	}
 out:
	if (buffer)
	    free(buffer);
	fclose(f);
    }

    return rv;
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
    int           event_only = 0;
    const char *tok;
    ipmi_sensor_handler_t *handler = NULL;
    unsigned int poll_rate = 0;
    void *rcb_data = NULL;
    const char *errstr;

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

    /*
     * FIXME - the depends that is part of the polled file sensor should
     * really be part of the main sensor structure.
     */
    tok = mystrtok(NULL, " \t\n", toks);
    while (tok) {
	if (strcmp(tok, "poll") == 0) {
	    if (handler) {
		out->printf(out, "**poll given twice in sensor\n", tok);
		return -1;
	    }

	    rv = emu_get_uint(out, toks, &poll_rate, "poll rate");
	    if (rv)
		return rv;

	    tok = mystrtok(NULL, " \t\n", toks);
	    if (!tok) {
		out->printf(out, "**No polled sensor handler given\n", tok);
		return -1;
	    }

	    handler = ipmi_sensor_find_handler(tok);
	    if (!handler) {
		out->printf(out, "**Invalid sensor handler: %s\n", tok);
		return -1;
	    }

	    rv = handler->init(mc, lun, num, toks, handler->cb_data, &rcb_data,
			       &errstr);
	    if (rv) {
		out->printf(out, "**Error initializing sensor handler: %s\n", 
			    errstr);
		return rv;
	    }
	} else if (strcmp(tok, "event-only") == 0) {
	    event_only = 1;
	} else {
	    out->printf(out, "**Unknown sensor option: %s\n", tok);
	    return -1;
	}

	tok = mystrtok(NULL, " \t\n", toks);
    }

    if (handler && event_only) {
	out->printf(out, "**An event-only sensor cannot be polled\n");
	return -1;
    }

    if (handler) {
	rv = ipmi_mc_add_polled_sensor(mc, lun, num, type, code,
				       poll_rate, handler->poll, rcb_data);
	
	if (!rv && handler->postinit) {
	    rv = handler->postinit(rcb_data, &errstr);
	    if (rv) {
		out->printf(out, "**Error in sensor handler postinit: %s\n", 
			    errstr);
	    }
	}
    } else {
	rv = ipmi_mc_add_sensor(mc, lun, num, type, code, event_only);
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
    uint16_t      enabled;
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

    rv = emu_get_bitmask(out, toks, &enabled, "threshold enabled", 6, 0);
    if (rv)
	return rv;

    for (i=5; i>=0; i--) {
	rv = emu_get_uchar(out, toks, &thresholds[i], "threshold value", 0);
	if (rv)
	    return rv;
    }

    rv = ipmi_mc_sensor_set_threshold(mc, lun, num, support,
				      enabled, 1, thresholds);
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
    uint16_t      assert_support;
    uint16_t      deassert_support;
    uint16_t      assert_enabled;
    uint16_t      deassert_enabled;

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

    rv = emu_get_bitmask(out, toks, &assert_support, "assert support", 15, 0);
    if (rv)
	return rv;

    rv = emu_get_bitmask(out, toks, &deassert_support, "deassert support",
			 15, 0);
    if (rv)
	return rv;

    rv = emu_get_bitmask(out, toks, &assert_enabled, "assert enabled", 15, 0);
    if (rv)
	return rv;

    rv = emu_get_bitmask(out, toks, &deassert_enabled, "deassert enabled",
			 15, 0);
    if (rv)
	return rv;

    rv = ipmi_mc_sensor_set_event_support(mc, lun, num,
					  1, events_enable, 1, scanning,
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
    unsigned int  flags = 0;
    int           rv;
    const char    *tok;
    
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

    while ((tok = mystrtok(NULL, " \t\n", toks))) {
	if (strcmp("dynsens", tok) == 0)
	    flags |= IPMI_MC_DYNAMIC_SENSOR_POPULATION;
	else if (strcmp("persist_sdr", tok) == 0)
	    flags |= IPMI_MC_PERSIST_SDR;
	else {
	    out->printf(out, "**Invalid MC flag: %s\n", tok);
	    return -1;
	}
    }

    mfg_id[0] = mfg_id_i & 0xff;
    mfg_id[1] = (mfg_id_i >> 8) & 0xff;
    mfg_id[2] = (mfg_id_i >> 16) & 0xff;
    product_id[0] = product_id_i & 0xff;
    product_id[1] = (product_id_i >> 8) & 0xff;
    rv = ipmi_emu_add_mc(emu, ipmb, device_id, has_device_sdrs,
			 device_revision, major_fw_rev, minor_fw_rev,
			 device_support, mfg_id, product_id, flags);
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
    const char    *tok;
    const char    *errstr;

    rv = emu_get_uchar(out, toks, &devid, "Device ID", 0);
    if (rv)
	return rv;

    rv = emu_get_uint(out, toks, &length, "FRU physical size");
    if (rv)
	return rv;

    tok = mystrtok(NULL, " \t\n", toks);
    if (!tok) {
	out->printf(out, "**No FRU data type given");
	return -1;
    }
    if (strcmp(tok, "file") == 0) {
	unsigned int file_offset;

	rv = emu_get_uint(out, toks, &file_offset, "file offset");
	if (rv)
	    return rv;

	rv = get_delim_str(toks, &tok, &errstr);
	if (rv) {
	    out->printf(out, "**Error with FRU filename: %d", strerror(rv));
	    return rv;
	}
	rv = ipmi_mc_add_fru_file(mc, devid, length, file_offset, (void *) tok);
	if (rv)
	    out->printf(out, "**Unable to add FRU file, error 0x%x\n", rv);
	
    } else if (strcmp(tok, "data") == 0) {
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
    } else {
	out->printf(out, "**FRU type not given, need file or data\n");
	rv = EINVAL;
    }
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
    const char *filename, *errstr;
    int err;

    err = get_delim_str(toks, &filename, &errstr);
    if (err) {
	out->printf(out, "Could not get include filename: %s\n", errstr);
	return err;
    }

    err = read_command_file(out, emu, filename);
    if (err == ENOENT &&
	filename[0] != '/' &&
	strncmp(filename, "./", 2) &&
	strncmp(filename, "../", 3))
    {
	char *nf = malloc(strlen(BASE_CONF_STR) + strlen(filename) + 2);
	if (!nf) {
	    out->printf(out, "Out of memory in include\n", errstr);
	    goto out_err;
	}
	strcpy(nf, BASE_CONF_STR);
	strcat(nf, "/");
	strcat(nf, filename);
	free((char *) filename);
	filename = nf;
	err = read_command_file(out, emu, filename);
	if (err) {
	    out->printf(out, "Could not read include file %s\n", filename);
	}
    }

  out_err:
    free((char *) filename);
    return err;
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
    unsigned int level = 0;
    const char   *tok;

    while ((tok = mystrtok(NULL, " \t\n", toks))) {
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
persist_cmd(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    const char *tok;

    while ((tok = mystrtok(NULL, " \t\n", toks))) {
	if (strcmp(tok, "on") == 0) {
	    persist_enable = 1;
	} else if (strcmp(tok, "off") == 0) {
	    persist_enable = 0;
	} else {
	    out->printf(out, "Invalid persist vale '%s', options are 'on' and 'off'\n",
		   tok);
	    return EINVAL;
	}
    }
    return 0;
}

static int
quit(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    fflush(stdout);
    ipmi_emu_shutdown(emu);
    return 0;
}

static int
do_define(emu_out_t *out, emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    const char *name, *value;
    int err;
    const char *errstr;

    name = mystrtok(NULL, " \t\n", toks);
    if (!name) {
	out->printf(out, "No variable name given for define\n");
	return EINVAL;
    }
    err = get_delim_str(toks, &value, &errstr);
    if (err) {
	out->printf(out, "Could not get variable %s value: %s\n", name, errstr);
	return err;
    }
    err = add_variable(name, value);
    if (err) {
	out->printf(out, "Out of memory setting variable %s\n", name);
	return err;
    }
    return 0;
}

struct emu_cmd_info {
    const char           *name;
    unsigned int         flags;
    ipmi_emu_cmd_handler handler;
    struct emu_cmd_info  *next;
};

static struct emu_cmd_info cmds[] =
{
    { "quit",		NOMC,		quit,			 &cmds[1] },
    { "define",		NOMC,		do_define,		 &cmds[2] },
    { "sel_enable",	MC,		sel_enable,		 &cmds[3] },
    { "sel_add",	MC,		sel_add,		 &cmds[4] },
    { "main_sdr_add",	MC,		main_sdr_add,		 &cmds[5] },
    { "device_sdr_add",	MC,		device_sdr_add,		 &cmds[6] },
    { "sensor_add",     MC,		sensor_add,		 &cmds[7] },
    { "sensor_set_bit", MC,		sensor_set_bit,		 &cmds[8] },
    { "sensor_set_bit_clr_rest", MC,	sensor_set_bit_clr_rest, &cmds[9] },
    { "sensor_set_value", MC,           sensor_set_value,	 &cmds[10] },
    { "sensor_set_hysteresis", MC,      sensor_set_hysteresis,	 &cmds[11] },
    { "sensor_set_threshold", MC,       sensor_set_threshold,	 &cmds[12] },
    { "sensor_set_event_support", MC,   sensor_set_event_support,&cmds[13] },
    { "mc_set_power",   MC,		mc_set_power,		 &cmds[14] },
    { "mc_add_fru_data",MC,		mc_add_fru_data,	 &cmds[15] },
    { "mc_dump_fru_data",MC,		mc_dump_fru_data,	 &cmds[16] },
    { "mc_set_num_leds",MC,		mc_set_num_leds,	 &cmds[17] },
    { "mc_add",		NOMC,		mc_add,			 &cmds[18] },
    { "mc_delete",	MC,		mc_delete,		 &cmds[19] },
    { "mc_disable",	MC,		mc_disable,		 &cmds[20] },
    { "mc_enable",	MC,		mc_enable,		 &cmds[21] },
    { "mc_setbmc",      NOMC,		mc_setbmc,		 &cmds[22] },
    { "mc_set_guid",	MC,		mc_set_guid,		 &cmds[23] },
    { "atca_enable",    NOMC,	        atca_enable,		 &cmds[24] },
    { "atca_set_site",	NOMC,		atca_set_site,		 &cmds[25] },
    { "read_cmds",	NOMC,		read_cmds,		 &cmds[26] },
    { "include",	NOMC,		read_cmds,		 &cmds[27] },
    { "sleep",		NOMC,		sleep_cmd,		 &cmds[28] },
    { "debug",		NOMC,		debug_cmd,		 &cmds[29] },
    { "persist",	NOMC,		persist_cmd,		 NULL },
    { NULL }
};

static struct emu_cmd_info *cmdlist = &cmds[0];

int
ipmi_emu_add_cmd(const char *name, unsigned int flags,
		 ipmi_emu_cmd_handler handler)
{
    struct emu_cmd_info *mcmd;

    mcmd = malloc(sizeof(*mcmd));
    if (!mcmd)
	return ENOMEM;
    mcmd->name = strdup(name);
    if (!mcmd->name) {
	free(mcmd);
	return ENOMEM;
    }
    mcmd->flags = flags;
    mcmd->handler = handler;
    mcmd->next = cmdlist;
    cmdlist = mcmd;
    return 0;
}

int
ipmi_emu_cmd(emu_out_t *out, emu_data_t *emu, char *cmd_str)
{
    char       *toks;
    const char *cmd;
    int        rv = EINVAL;
    lmc_data_t *mc = NULL;
    struct emu_cmd_info *mcmd;

    cmd = mystrtok(cmd_str, " \t\n", &toks);
    if (!cmd)
	return 0;
    if (cmd[0] == '#')
	return 0;

    
    for (mcmd = cmdlist; mcmd; mcmd = mcmd->next) {
	if (strcmp(cmd, mcmd->name) == 0) {
	    if (mcmd->flags & MC) {
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
	    rv = mcmd->handler(out, emu, mc, &toks);
	    if (rv)
		return rv;
	    goto out;
	}
    }

    out->printf(out, "**Unknown command: %s\n", cmd);

 out:
    return rv;
}
