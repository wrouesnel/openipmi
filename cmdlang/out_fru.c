/*
 * out_fru.c
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
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <OpenIPMI/ipmi_int.h>

static void
fru_out_data(ipmi_cmd_info_t *cmd_info, unsigned char type,
	     char *buf, unsigned int len)
{
    if (type == IPMI_BINARY_STR) {
	ipmi_cmdlang_out(cmd_info, "Type", "binary");
	ipmi_cmdlang_out_binary(cmd_info, "Binary Data", buf, len);
    } else if (type == IPMI_UNICODE_STR) {
	ipmi_cmdlang_out(cmd_info, "Type", "unicode");
	ipmi_cmdlang_out_unicode(cmd_info, "Data", buf, len);
    } else if (type == IPMI_ASCII_STR) {
	ipmi_cmdlang_out(cmd_info, "Type", "ascii");
	ipmi_cmdlang_out(cmd_info, "Data", buf);
    } else {
	ipmi_cmdlang_out(cmd_info, "Type", "unknown");
    }
}

static void
dump_fru_str(ipmi_cmd_info_t *cmd_info,
	     ipmi_fru_t *fru,
	     char       *str,
	     int (*glen)(ipmi_fru_t   *fru,
			 unsigned int *length),
	     int (*gtype)(ipmi_fru_t           *fru,
			  enum ipmi_str_type_e *type),
	     int (*gstr)(ipmi_fru_t   *fru,
			 char         *str,
			 unsigned int *strlen))
{
    ipmi_cmdlang_t  *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    enum ipmi_str_type_e type;
    int          rv = 0;
    char         *buf = NULL;
    unsigned int len;

    if (cmdlang->err)
	return;

    rv = gtype(fru, &type);
    if (!rv)
	rv = glen(fru, &len);
    if (!rv) {
	buf = ipmi_mem_alloc(len);
	if (!buf) {
	    rv = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	    goto out_err;
	}
	rv = gstr(fru, buf, &len);
	if (rv)
	    ipmi_mem_free(buf);
    }
    if (rv) {
	if (rv != ENOSYS)
	    cmdlang->errstr = "Error getting FRU info";
	goto out_err;
    }

    ipmi_cmdlang_out(cmd_info, "Record", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", str);
    fru_out_data(cmd_info, type, buf, len);
    ipmi_cmdlang_up(cmd_info);

 out_err:
    if (rv) {
	if (rv != ENOSYS) {
	    cmdlang->err = rv;
	    cmdlang->location = "cmd_domain.c(dump_fru_str)";
	}
    } else
	ipmi_mem_free(buf);
}

static int
dump_fru_custom_str(ipmi_cmd_info_t *cmd_info,
		    ipmi_fru_t *fru,
		    char       *str,
		    int        num,
		    int (*glen)(ipmi_fru_t   *fru,
				unsigned int num,
				unsigned int *length),
		    int (*gtype)(ipmi_fru_t           *fru,
				 unsigned int         num,
				 enum ipmi_str_type_e *type),
		    int (*gstr)(ipmi_fru_t   *fru,
				unsigned int num,
				char         *str,
				unsigned int *strlen))
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    enum ipmi_str_type_e type;
    int          rv = 0;
    char         *buf = NULL;
    unsigned int len;

    if (cmdlang->err)
	return cmdlang->err;

    rv = gtype(fru, num, &type);
    if (!rv)
	rv = glen(fru, num, &len);
    if (!rv) {
	buf = ipmi_mem_alloc(len);
	if (!buf) {
	    rv = ENOMEM;
	    cmdlang->errstr = "Out of memory";
	    goto out_err;
	}
	rv = gstr(fru, num, buf, &len);
	if (rv)
	    ipmi_mem_free(buf);
    }
    if (rv) {
	if (rv != ENOSYS)
	    cmdlang->errstr = "Error getting FRU info";
	goto out_err;
    }

    ipmi_cmdlang_out(cmd_info, "String Field", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_cmdlang_out(cmd_info, "Name", str);
    ipmi_cmdlang_out_int(cmd_info, "Number", num);
    fru_out_data(cmd_info, type, buf, len);
    ipmi_cmdlang_up(cmd_info);

 out_err:
    if (rv) {
	if (rv != ENOSYS) {
	    cmdlang->err = rv;
	    cmdlang->location = "cmd_domain.c(dump_fru_custom_str)";
	}
    } else
	ipmi_mem_free(buf);
    return rv;
}

#define DUMP_FRU_STR(name, str) \
dump_fru_str(cmd_info, fru, str, ipmi_fru_get_ ## name ## _len, \
             ipmi_fru_get_ ## name ## _type, \
             ipmi_fru_get_ ## name)

#define DUMP_FRU_CUSTOM_STR(name, str) \
do {									\
    int i, _rv;								\
    for (i=0; ; i++) {							\
        _rv = dump_fru_custom_str(cmd_info, fru, str, i,		\
				  ipmi_fru_get_ ## name ## _custom_len, \
				  ipmi_fru_get_ ## name ## _custom_type, \
				  ipmi_fru_get_ ## name ## _custom);	\
	if (_rv)							\
	    break;							\
    }									\
} while (0)

void
ipmi_cmdlang_dump_fru_info(ipmi_cmd_info_t *cmd_info, ipmi_fru_t *fru)
{
    ipmi_cmdlang_t *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    unsigned char ucval;
    unsigned int  uival;
    time_t        tval;
    int           rv;
    int           i, num_multi;
    unsigned char *buf;

    ipmi_cmdlang_out(cmd_info, "FRU", NULL);
    ipmi_cmdlang_down(cmd_info);
    rv = ipmi_fru_get_internal_use_version(fru, &ucval);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Internal area version", ucval);

    rv = ipmi_fru_get_internal_use_length(fru, &uival);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Internal area length", uival);

    buf = ipmi_mem_alloc(uival);
    if (!buf) {
	cmdlang->err = ENOMEM;
	cmdlang->errstr = "Out of memory";
	goto out_err;
    }
    ipmi_cmdlang_out_binary(cmd_info, "Internal area data", buf, uival);
    ipmi_mem_free(buf);

    rv = ipmi_fru_get_chassis_info_version(fru, &ucval);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Chassis info version", ucval);

    rv = ipmi_fru_get_chassis_info_type(fru, &ucval);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Chassis info type", ucval);

    DUMP_FRU_STR(chassis_info_part_number, "chassis info part number");
    DUMP_FRU_STR(chassis_info_serial_number, "chassis info serial number");
    DUMP_FRU_CUSTOM_STR(chassis_info, "chassis info");

    rv = ipmi_fru_get_board_info_version(fru, &ucval);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Board info version", ucval);

    rv = ipmi_fru_get_board_info_lang_code(fru, &ucval);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "Board info lang code", ucval);

    rv = ipmi_fru_get_board_info_mfg_time(fru, &tval);
    if (!rv)
	ipmi_cmdlang_out_long(cmd_info, "Board info mfg time", (long) tval);

    DUMP_FRU_STR(board_info_board_manufacturer,
		 "board info board manufacturer");
    DUMP_FRU_STR(board_info_board_product_name,
		 "board info board product name");
    DUMP_FRU_STR(board_info_board_serial_number,
		 "board info board serial number");
    DUMP_FRU_STR(board_info_board_part_number,
		 "board info board part number");
    DUMP_FRU_STR(board_info_fru_file_id, "board info fru file id");
    DUMP_FRU_CUSTOM_STR(board_info, "board info");

    rv = ipmi_fru_get_product_info_version(fru, &ucval);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "product info version", ucval);

    rv = ipmi_fru_get_product_info_lang_code(fru, &ucval);
    if (!rv)
	ipmi_cmdlang_out_int(cmd_info, "product info lang code", ucval);

    DUMP_FRU_STR(product_info_manufacturer_name,
		 "product info manufacturer name");
    DUMP_FRU_STR(product_info_product_name, "product info product name");
    DUMP_FRU_STR(product_info_product_part_model_number,
		 "product info product part model number");
    DUMP_FRU_STR(product_info_product_version, "product info product version");
    DUMP_FRU_STR(product_info_product_serial_number,
		 "product info product serial number");
    DUMP_FRU_STR(product_info_asset_tag, "product info asset tag");
    DUMP_FRU_STR(product_info_fru_file_id, "product info fru file id");
    DUMP_FRU_CUSTOM_STR(product_info, "product info");
    num_multi = ipmi_fru_get_num_multi_records(fru);
    for (i=0; i<num_multi; i++) {
	unsigned char type, ver;
	unsigned int  len;
	char          *data;

	rv = ipmi_fru_get_multi_record_type(fru, i, &type);
	if (!rv)
	    rv = ipmi_fru_get_multi_record_format_version(fru, i, &ver);
	if (!rv)
	    rv = ipmi_fru_get_multi_record_data_len(fru, i, &len);
	if (!rv) {
	    data = ipmi_mem_alloc(len);
	    if (!data) {
		cmdlang->err = ENOMEM;
		cmdlang->errstr = "Out of memory";
		goto out_err;
	    }
	    rv = ipmi_fru_get_multi_record_data(fru, i, data, &len);
	    if (rv)
		ipmi_mem_free(data);
	}

	if (rv) {
	    cmdlang->err = rv;
	    cmdlang->errstr = "Error getting FRU info";
	    goto out_err;
	}

	ipmi_cmdlang_out(cmd_info, "Multi-record", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out_int(cmd_info, "Number", i);
	fru_out_data(cmd_info, type, data, len);
	ipmi_cmdlang_up(cmd_info);
	ipmi_mem_free(data);
    }

 out_err:
    ipmi_cmdlang_up(cmd_info);
    if (cmdlang->err)
	cmdlang->location = "cmd_domain.c(dump_fru_info)";
}
