
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include "emu.h"

typedef void (*ipmi_emu_cmd_handler)(emu_data_t *emu,
				     lmc_data_t *mc,
				     char       **toks);

static int
get_uchar(char **toks, unsigned char *val, char *errstr)
{
    char *str, *tmpstr;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (errstr)
	    printf("No %s given\n", errstr);
	return EINVAL;
    }
    *val = strtoul(str, &tmpstr, 16);
    if (*tmpstr != '\0') {
	if (errstr)
	    printf("Invalid %s given\n", errstr);
	return EINVAL;
    }

    return 0;
}

static int
get_uint(char **toks, unsigned int *val, char *errstr)
{
    char *str, *tmpstr;

    str = strtok_r(NULL, " \t\n", toks);
    if (!str) {
	if (errstr)
	    printf("No %s given\n", errstr);
	return EINVAL;
    }
    *val = strtoul(str, &tmpstr, 16);
    if (*tmpstr != '\0') {
	if (errstr)
	    printf("Invalid %s given\n", errstr);
	return EINVAL;
    }

    return 0;
}

static void
sel_enable(emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           rv;
    unsigned int  max_records;
    unsigned char flags;

    rv = get_uint(toks, &max_records, "flags");
    if (rv)
	return;

    rv = get_uchar(toks, &flags, "flags");
    if (rv)
	return;

    rv = ipmi_mc_enable_sel(mc, max_records, flags);
    if (rv)
	printf("Unable to enable sel, error 0x%x\n", rv);
}

static void
sel_add(emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    int           i;
    int           rv;
    unsigned char record_type;
    unsigned char data[13];

    rv = get_uchar(toks, &record_type, "record type");
    if (rv)
	return;

    for (i=0; i<13; i++) {
	rv = get_uchar(toks, &data[i], "data byte");
	if (rv)
	    return;
    }

    rv = ipmi_mc_add_to_sel(mc, record_type, data);
    if (rv)
	printf("Unable to add to sel, error 0x%x\n", rv);
}

void
mc_add(emu_data_t *emu, lmc_data_t *mc, char **toks)
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
    int           rv;
    
    if (get_uchar(toks, &ipmb, "IPMB address"))
	return;
    if (get_uchar(toks, &device_id, "Device ID"))
	return;
    if (get_uchar(toks, &has_device_sdrs, "Has Device SDRs"))
	return;
    if (get_uchar(toks, &device_revision, "Device Revision"))
	return;
    if (get_uchar(toks, &major_fw_rev, "Major FW Rev"))
	return;
    if (get_uchar(toks, &minor_fw_rev, "Minor FW Rev"))
	return;
    if (get_uchar(toks, &device_support, "Device Support"))
	return;
    if (get_uint(toks, &mfg_id_i, "Manufacturer ID"))
	return;
    if (get_uint(toks, &product_id_i, "Product ID"))
	return;
    mfg_id[0] = mfg_id_i & 0xff;
    mfg_id[1] = (mfg_id_i >> 8) & 0xff;
    mfg_id[2] = (mfg_id_i >> 16) & 0xff;
    product_id[0] = product_id_i & 0xff;
    product_id[1] = (product_id_i >> 8) & 0xff;
    rv = ipmi_emu_add_mc(emu, ipmb, device_id, has_device_sdrs,
			 device_revision, major_fw_rev, minor_fw_rev,
			 device_support, mfg_id, product_id);
    if (rv)
	printf("Unable to add the MC, error 0x%x\n", rv);
}

static void
mc_setbmc(emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    unsigned char ipmb;

    if (get_uchar(toks, &ipmb, "IPMB address of BMC"))
	return;
    if (ipmi_emu_set_bmc_mc(emu, ipmb)) {
	printf("Invalid IPMB address\n");
	return;
    }
}

static void
read_cmds(emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    char *filename = strtok_r(NULL, " \t\n", toks);
    FILE *f;
    char buffer[1024];

    if (!filename) {
	printf("No filename specified\n");
	return;
    }

    f = fopen(filename, "r");
    if (!f) {
	printf("Unable to open file '%s', %s\n", filename, strerror(errno));
	return;
    }

    while (fgets(buffer, sizeof(buffer), f)) {
	printf("%s", buffer);
	ipmi_emu_cmd(emu, buffer);
    }
}

static void
quit(emu_data_t *emu, lmc_data_t *mc, char **toks)
{
    ipmi_emu_shutdown();
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
    { "mc_add",		NOMC,		mc_add },
    { "mc_setbmc",      NOMC,		mc_setbmc },
    { "read_cmds",	NOMC,		read_cmds },
    { NULL }
};

void
ipmi_emu_cmd(emu_data_t *emu, char *cmd_str)
{
    char       *toks;
    char       *cmd;
    int        i;
    int        rv;
    lmc_data_t *mc = NULL;

    cmd = strtok_r(cmd_str, " \t\n", &toks);
    if (!cmd)
	return;
    if (cmd[0] == '#')
	return;

    for (i=0; cmds[i].name; i++) {
	if (strcmp(cmd, cmds[i].name) == 0) {
	    if (cmds[i].flags & MC) {
		unsigned char ipmb;
		if (get_uchar(&toks, &ipmb, "MC address"))
		    return;
		rv = ipmi_emu_get_mc_by_addr(emu, ipmb, &mc);
		if (rv) {
		    printf("Invalid MC address\n");
		    return;
		}
	    }
	    cmds[i].handler(emu, mc, &toks);
	    goto out;
	}
    }

    printf("Unknown command: %s\n", cmd);

 out:
    return;
}
