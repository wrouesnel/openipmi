/*
 * cmd_fru.c
 *
 * A command interpreter for OpenIPMI
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004 MontaVista Software Inc.
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

#include <errno.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdio.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_fru.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_malloc.h>

/* Don't pollute the namespace iwth ipmi_fru_t. */
void ipmi_cmdlang_dump_fru_info(ipmi_cmd_info_t *cmd_info, ipmi_fru_t *fru);

static void
fru_list_handler(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            fru_name[IPMI_FRU_NAME_LEN];

    if (cmdlang->err)
	return;

    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));

    ipmi_cmdlang_out(cmd_info, "Name", fru_name);
}

static void
fru_list(ipmi_domain_t *domain, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char             domain_name[IPMI_DOMAIN_NAME_LEN];

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    ipmi_cmdlang_out(cmd_info, "Domain", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", domain_name);
    ipmi_cmdlang_out(cmd_info, "FRUs", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_fru_iterate_frus(domain, fru_list_handler, cmd_info);
    ipmi_cmdlang_up(cmd_info);
    ipmi_cmdlang_up(cmd_info);
}

static void
fru_info(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            fru_name[IPMI_FRU_NAME_LEN];

    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));

    ipmi_cmdlang_dump_fru_info(cmd_info, fru);
}

static char *areas[IPMI_FRU_FTR_NUMBER] =
{
    "internal_use",
    "chassis_info",
    "board_info",
    "product_info",
    "multi_record"
};

static void
fru_areainfo(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            fru_name[IPMI_FRU_NAME_LEN];
    int             i;
    int             rv;

    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));

    ipmi_cmdlang_out(cmd_info, "FRU", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", fru_name);
    ipmi_cmdlang_out_int(cmd_info, "FRU Length",
			 ipmi_fru_get_data_length(fru));
    for (i=0; i<IPMI_FRU_FTR_NUMBER; i++) {
	unsigned int offset, length, used_length;
	rv = ipmi_fru_area_get_offset(fru, i, &offset);
	rv |= ipmi_fru_area_get_length(fru, i, &length);
	rv |= ipmi_fru_area_get_used_length(fru, i, &used_length);
	if (rv)
	    continue;
	ipmi_cmdlang_out(cmd_info, "Area", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name", areas[i]);
	ipmi_cmdlang_out_int(cmd_info, "Number", i);
	ipmi_cmdlang_out_int(cmd_info, "Offset", offset);
	ipmi_cmdlang_out_int(cmd_info, "Length", length);
	ipmi_cmdlang_out_int(cmd_info, "Used Length", used_length);
	ipmi_cmdlang_up(cmd_info);
    }
    ipmi_cmdlang_up(cmd_info);
}

static void
fru_written(ipmi_domain_t *domain, ipmi_fru_t *fru, int err, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    char            fru_name[IPMI_FRU_NAME_LEN];

    if (err) {
	cmdlang->errstr = "Unable to write FRU";
	cmdlang->err = err;
	ipmi_fru_get_name(fru, cmdlang->objstr,
			  cmdlang->objstr_len);
	cmdlang->location = "cmd_fru.c(fru_written)";
    } else {
	ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));
	ipmi_cmdlang_out(cmd_info, "FRU written", fru_name);
    }

    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
fru_write(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    rv = ipmi_fru_write(fru, fru_written, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Unable to write FRU";
	cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    ipmi_fru_get_name(fru, cmdlang->objstr,
		      cmdlang->objstr_len);
    cmdlang->location = "cmd_fru.c(fru_write)";
}

static void
fru_deleted(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    char            fru_name[IPMI_FRU_NAME_LEN];

    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));
    ipmi_cmdlang_out(cmd_info, "FRU deleted", fru_name);
    ipmi_cmdlang_cmd_info_put(cmd_info);
}

static void
fru_close(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             rv;

    ipmi_cmdlang_cmd_info_get(cmd_info);
    /* We need to be holding our own reference to the FRU because
       ipmi_fru_destroy will do a deref on it, but the calling code
       will also be doing a deref.. */
    ipmi_fru_ref(fru);
    rv = ipmi_fru_destroy(fru, fru_deleted, cmd_info);
    if (rv) {
	ipmi_cmdlang_cmd_info_put(cmd_info);
	cmdlang->errstr = "Unable to close domain";
	cmdlang->err = rv;
	goto out_err;
    }

    return;

 out_err:
    ipmi_fru_get_name(fru, cmdlang->objstr,
		      cmdlang->objstr_len);
    cmdlang->location = "cmd_fru.c(fru_close)";
}

static void
fru_setval(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    char            fru_name[IPMI_FRU_NAME_LEN];
    enum ipmi_fru_data_type_e dtype;
    int             i;
    int             num;
    const char      *name;
    int             ival;
    double          dval;
    int             rv;
    int             len;
    unsigned char   *data;
    int             j;
    int             type;
    int             version;

    if ((argc - curr_arg) < 2) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    if (strcmp(argv[curr_arg], "multi_record") == 0)
	goto do_multi_record;

    for (i=0; ; i++) {
	num = -2;
	rv = ipmi_fru_get(fru, i, &name, &num, &dtype, NULL, NULL, NULL, NULL);
	if (rv == EINVAL) {
	    cmdlang->errstr = "Name not found";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	if (strcmp(name, argv[curr_arg]) == 0)
	    break;
    }
    curr_arg++;

    if (num != -2) {
	/* Need the number */
	ipmi_cmdlang_get_int(argv[curr_arg], &num, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "value number";
	    goto out_err;
	}
	curr_arg++;

	if ((argc - curr_arg) < 1) {
	    /* Not enough parameters */
	    cmdlang->errstr = "Not enough parameters";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
    }

    switch (dtype) {
    case IPMI_FRU_DATA_TIME:
	ipmi_cmdlang_get_int(argv[curr_arg], &ival, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "value invalid";
	    goto out_err;
	}
	curr_arg++;
	rv = ipmi_fru_set_time_val(fru, i, num, ival);
	if (rv) {
	    cmdlang->errstr = "value invalid";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	break;

    case IPMI_FRU_DATA_INT:
	ipmi_cmdlang_get_int(argv[curr_arg], &ival, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "value invalid";
	    goto out_err;
	}
	curr_arg++;
	rv = ipmi_fru_set_int_val(fru, i, num, ival);
	if (rv) {
	    cmdlang->errstr = "value invalid";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	break;

    case IPMI_FRU_DATA_BOOLEAN:
	ipmi_cmdlang_get_bool(argv[curr_arg], &ival, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "value invalid";
	    goto out_err;
	}
	curr_arg++;
	rv = ipmi_fru_set_int_val(fru, i, num, ival);
	if (rv) {
	    cmdlang->errstr = "value invalid";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	break;

    case IPMI_FRU_DATA_FLOAT:
	ipmi_cmdlang_get_double(argv[curr_arg], &dval, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "value invalid";
	    goto out_err;
	}
	curr_arg++;
	rv = ipmi_fru_set_float_val(fru, i, num, dval);
	if (rv) {
	    cmdlang->errstr = "value invalid";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	break;

    case IPMI_FRU_DATA_ASCII:
    case IPMI_FRU_DATA_BINARY:
    case IPMI_FRU_DATA_UNICODE:
	if ((argc - curr_arg) < 1) {
	    /* Not enough parameters */
	    cmdlang->errstr = "Not enough parameters";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	if (strcasecmp(argv[curr_arg], "binary") == 0) {
	    dtype = IPMI_FRU_DATA_BINARY;
	} else if (strcasecmp(argv[curr_arg], "ascii") == 0) {
	    dtype = IPMI_FRU_DATA_ASCII;
	} else if (strcasecmp(argv[curr_arg], "unicode") == 0) {
	    dtype = IPMI_FRU_DATA_UNICODE;
	} else {
	    cmdlang->errstr = "Invalid data type";
	    cmdlang->err = EINVAL;
	    goto out_err;
	}
	curr_arg++;
	if (dtype == IPMI_FRU_DATA_ASCII) {
	    char *str;
	    int  len;
	    if (curr_arg < argc) {
		str = argv[curr_arg];
		len = strlen(str);
	    } else {
		str = NULL;
		len = 0;
	    }
	    rv = ipmi_fru_set_data_val(fru, i, num, dtype, str, len);
	} else {
	    len = argc - curr_arg;

	    if (len == 0)
		data = ipmi_mem_alloc(1);
	    else
		data = ipmi_mem_alloc(len);
	    if (!data) {
		cmdlang->errstr = "Out of memory";
		cmdlang->err = ENOMEM;
		goto out_err;
	    }
	    j = 0;
	    while (curr_arg < argc) {
		ipmi_cmdlang_get_int(argv[curr_arg], &ival, cmd_info);
		if (cmdlang->err) {
		    cmdlang->errstr = "value invalid";
		    ipmi_mem_free(data);
		    goto out_err;
		}
		data[j] = ival;
		curr_arg++;
		j++;
	    }
	    rv = ipmi_fru_set_data_val(fru, i, num, dtype, (char *) data, len);
	    ipmi_mem_free(data);
	}
	if (rv) {
	    cmdlang->errstr = "Error setting data value";
	    cmdlang->err = rv;
	    goto out_err;
	}

    case IPMI_FRU_DATA_SUB_NODE:
	/* Not relevant for normal FRU data. */
	break;
    }

    goto out;

 do_multi_record:
    curr_arg++;
    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &num, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "value number";
	goto out_err;
    }
    curr_arg++;

    if ((argc - curr_arg) == 0) {
	/* Deleting the record. */
	rv = ipmi_fru_set_multi_record(fru, num, 0, 0, NULL, 0);
	if (rv) {
	    cmdlang->errstr = "Error clearing data value";
	    cmdlang->err = rv;
	    goto out_err;
	}
	goto out;
    }

    if ((argc - curr_arg) < 2) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    ipmi_cmdlang_get_int(argv[curr_arg], &type, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "type number";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &version, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "version number";
	goto out_err;
    }
    curr_arg++;

    len = argc - curr_arg;

    if (len == 0)
	data = ipmi_mem_alloc(1);
    else
	data = ipmi_mem_alloc(len);
    if (!data) {
	cmdlang->errstr = "Out of memory";
	cmdlang->err = ENOMEM;
	goto out_err;
    }
    j = 0;
    while (curr_arg < argc) {
	ipmi_cmdlang_get_int(argv[curr_arg], &ival, cmd_info);
	if (cmdlang->err) {
	    cmdlang->errstr = "value invalid";
	    ipmi_mem_free(data);
	    goto out_err;
	}
	data[j] = ival;
	curr_arg++;
	j++;
    }
    rv = ipmi_fru_set_multi_record(fru, num, type, version, data, len);
    ipmi_mem_free(data);
    if (rv) {
	cmdlang->errstr = "Error setting data value";
	cmdlang->err = rv;
	goto out_err;
    }

 out:
    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));
    ipmi_cmdlang_out(cmd_info, "FRU value set", fru_name);

    return;

 out_err:
    ipmi_fru_get_name(fru, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_fru.c(fru_setval)";
}

static void
get_fru_by_name(char *name, ipmi_cmdlang_t *cmdlang, unsigned int *area)
{
    if (strcmp(name, "internal_data") == 0) {
	*area = IPMI_FRU_FTR_INTERNAL_USE_AREA;
    } else if (strcmp(name, "chassis_info") == 0) {
	*area = IPMI_FRU_FTR_CHASSIS_INFO_AREA;
    } else if (strcmp(name, "board_info") == 0) {
	*area = IPMI_FRU_FTR_BOARD_INFO_AREA  ;
    } else if (strcmp(name, "product_info") == 0) {
	*area = IPMI_FRU_FTR_PRODUCT_INFO_AREA;
    } else if (strcmp(name, "multi_record") == 0) {
	*area = IPMI_FRU_FTR_MULTI_RECORD_AREA;
    } else {
	cmdlang->errstr = "Invalid area name";
	cmdlang->err = EINVAL;
    }
}

static void
fru_area_offset(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    char            fru_name[IPMI_FRU_NAME_LEN];
    unsigned int    area;
    int		    offset;
    int             rv;

    if ((argc - curr_arg) < 2) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    get_fru_by_name(argv[curr_arg], cmdlang, &area);
    if (cmdlang->err)
	goto out_err;
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &offset, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "offset invalid";
	goto out_err;
    }

    rv = ipmi_fru_area_set_offset(fru, area, offset);
    if (rv) {
	cmdlang->errstr = "Error setting area offset";
	cmdlang->err = rv;
	goto out_err;
    }

    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));
    ipmi_cmdlang_out(cmd_info, "FRU area offset set", fru_name);
    return;

 out_err:
    ipmi_fru_get_name(fru, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_fru.c(fru_area_offset)";
}

static void
fru_area_length(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    char            fru_name[IPMI_FRU_NAME_LEN];
    unsigned int    area;
    int		    length;
    int             rv;

    if ((argc - curr_arg) < 2) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    get_fru_by_name(argv[curr_arg], cmdlang, &area);
    if (cmdlang->err)
	goto out_err;
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &length, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "length invalid";
	goto out_err;
    }

    rv = ipmi_fru_area_set_length(fru, area, length);
    if (rv) {
	cmdlang->errstr = "Error setting area length";
	cmdlang->err = rv;
	goto out_err;
    }

    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));
    ipmi_cmdlang_out(cmd_info, "FRU area length set", fru_name);
    return;

 out_err:
    ipmi_fru_get_name(fru, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_fru.c(fru_area_length)";
}

static void
fru_area_add(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    char            fru_name[IPMI_FRU_NAME_LEN];
    unsigned int    area;
    int		    length, offset;
    int             rv;

    if ((argc - curr_arg) < 3) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    get_fru_by_name(argv[curr_arg], cmdlang, &area);
    if (cmdlang->err)
	goto out_err;
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &offset, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "offset invalid";
	goto out_err;
    }
    curr_arg++;

    ipmi_cmdlang_get_int(argv[curr_arg], &length, cmd_info);
    if (cmdlang->err) {
	cmdlang->errstr = "length invalid";
	goto out_err;
    }
    curr_arg++;

    rv = ipmi_fru_add_area(fru, area, offset, length);
    if (rv) {
	cmdlang->errstr = "Error adding area";
	cmdlang->err = rv;
	goto out_err;
    }

    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));
    ipmi_cmdlang_out(cmd_info, "FRU area added", fru_name);
    return;

 out_err:
    ipmi_fru_get_name(fru, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_fru.c(fru_area_add)";
}

static void
fru_area_delete(ipmi_fru_t *fru, void *cb_data)
{
    ipmi_cmd_info_t *cmd_info = cb_data;
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int             curr_arg = ipmi_cmdlang_get_curr_arg(cmd_info);
    int             argc = ipmi_cmdlang_get_argc(cmd_info);
    char            **argv = ipmi_cmdlang_get_argv(cmd_info);
    char            fru_name[IPMI_FRU_NAME_LEN];
    unsigned int    area;
    int             rv;

    if ((argc - curr_arg) < 1) {
	/* Not enough parameters */
	cmdlang->errstr = "Not enough parameters";
	cmdlang->err = EINVAL;
	goto out_err;
    }

    get_fru_by_name(argv[curr_arg], cmdlang, &area);
    if (cmdlang->err)
	goto out_err;
    curr_arg++;

    rv = ipmi_fru_delete_area(fru, area);
    if (rv) {
	cmdlang->errstr = "Error deleting area";
	cmdlang->err = rv;
	goto out_err;
    }

    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));
    ipmi_cmdlang_out(cmd_info, "FRU area deleted", fru_name);
    return;

 out_err:
    ipmi_fru_get_name(fru, cmdlang->objstr,
		     cmdlang->objstr_len);
    cmdlang->location = "cmd_fru.c(fru_area_delete)";
}

static ipmi_cmdlang_cmd_t *fru_cmds;

static ipmi_cmdlang_init_t cmds_fru[] =
{
    { "fru", NULL,
      "- Commands dealing with FRUs",
      NULL, NULL, &fru_cmds},
    { "list", &fru_cmds,
      "- List all the frus in the system",
      ipmi_cmdlang_domain_handler, fru_list,  NULL },
    { "info", &fru_cmds,
      "<fru> - Dump information about a FRU",
      ipmi_cmdlang_fru_handler, fru_info, NULL },
    { "areainfo", &fru_cmds,
      "<fru> - Dump the info about the FRU's areas",
      ipmi_cmdlang_fru_handler, fru_areainfo, NULL },
    { "write", &fru_cmds,
      "<fru> - Write the local FRU data out into the FRU",
      ipmi_cmdlang_fru_handler, fru_write, NULL },
    { "close", &fru_cmds,
      "<fru> - Delete the FRU",
      ipmi_cmdlang_fru_handler, fru_close, NULL },
    { "setval", &fru_cmds,
      "<fru> <name> [num] value - Set the value of a FRU element.  The"
      " name is the record name, or multi_record.  The number is required"
      " for fields that need it (custom and multi-record).  The value is"
      " an a single value for integers.  For strings it is a string"
      " type (either binary, ascii, or unicode) and the info.  Binary and"
      " unicode data is specified as numbers.  ascii data is specified in"
      " a string.  Note that setting a ascii value with no string will"
      " clear the value.  Zero length strings and data is valid.  For"
      " multi_record, the value is <type> <version> [<data> ...]",
      ipmi_cmdlang_fru_handler, fru_setval, NULL },
    { "area_offset", &fru_cmds,
      "<fru> <area name> <offset> - Set the offset of the given area"
      " to the given value.  Area names are internal_data, chassis_info,"
      " board_info, product_info, and multi_record",
      ipmi_cmdlang_fru_handler, fru_area_offset, NULL },
    { "area_length", &fru_cmds,
      "<fru> <area name> <length> - Set the length of the given area"
      " to the given value.  Area names are internal_data, chassis_info,"
      " board_info, product_info, and multi_record",
      ipmi_cmdlang_fru_handler, fru_area_length, NULL },
    { "area_add", &fru_cmds,
      "<fru> <area name> <offset> <length> - Add the given area to the FRU",
      ipmi_cmdlang_fru_handler, fru_area_add, NULL },
    { "area_delete", &fru_cmds,
      "<fru> <area name> - Delete the given area from the FRU",
      ipmi_cmdlang_fru_handler, fru_area_delete, NULL },
};
#define CMDS_FRU_LEN (sizeof(cmds_fru)/sizeof(ipmi_cmdlang_init_t))

int
ipmi_cmdlang_fru_init(os_handler_t *os_hnd)
{
    return ipmi_cmdlang_reg_table(cmds_fru, CMDS_FRU_LEN);
}
