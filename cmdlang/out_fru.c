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
#include <string.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_cmdlang.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_malloc.h>

static void
fru_out_data(ipmi_cmd_info_t *cmd_info, unsigned char type,
	     char *buf, unsigned int len)
{
    if (type == IPMI_BINARY_STR) {
	ipmi_cmdlang_out(cmd_info, "Type", "binary");
	ipmi_cmdlang_out_binary(cmd_info, "Data", buf, len);
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

static int
traverse_fru_multi_record_tree(ipmi_cmd_info_t *cmd_info,
			       ipmi_fru_node_t *node)
{
    const char                *name;
    unsigned int              i;
    enum ipmi_fru_data_type_e dtype;
    int                       intval, rv;
    time_t                    time;
    double                    floatval;
    char                      *data;
    unsigned int              data_len;
    ipmi_fru_node_t           *sub_node;
    
    for (i=0; ; i++) {
	data = NULL;
        rv = ipmi_fru_node_get_field(node, i, &name, &dtype, &intval, &time,
				     &floatval, &data, &data_len, &sub_node);
        if ((rv == EINVAL) || (rv == ENOSYS))
            break;
        else if (rv)
            continue;

	if (name) {
	    ipmi_cmdlang_out(cmd_info, "Field", NULL);
	    ipmi_cmdlang_down(cmd_info);
	    ipmi_cmdlang_out(cmd_info, "Name", name);
	} else {
	    ipmi_cmdlang_out(cmd_info, "Element", NULL);
	    ipmi_cmdlang_down(cmd_info);
	    ipmi_cmdlang_out_int(cmd_info, "Index", i);
	}

        switch (dtype) {
	case IPMI_FRU_DATA_INT:
	    ipmi_cmdlang_out(cmd_info, "Type", "integer");
	    ipmi_cmdlang_out_int(cmd_info, "Data", intval);
	    break;

	case IPMI_FRU_DATA_TIME:
	    ipmi_cmdlang_out(cmd_info, "Type", "integer");
	    ipmi_cmdlang_out_long(cmd_info, "Data", (long) time);
	    break;

	case IPMI_FRU_DATA_BINARY:
	    ipmi_cmdlang_out(cmd_info, "Type", "binary");
	    ipmi_cmdlang_out_binary(cmd_info, "Data", data, data_len);
	    break;

	case IPMI_FRU_DATA_UNICODE:
	    ipmi_cmdlang_out(cmd_info, "Type", "unicode");
	    ipmi_cmdlang_out_unicode(cmd_info, "Data", data, data_len);
	    break;

	case IPMI_FRU_DATA_ASCII:
	    ipmi_cmdlang_out(cmd_info, "Type", "ascii");
	    ipmi_cmdlang_out(cmd_info, "Data", data);
	    break;

	case IPMI_FRU_DATA_BOOLEAN:
	    ipmi_cmdlang_out(cmd_info, "Type", "boolean");
	    ipmi_cmdlang_out_bool(cmd_info, "Data", intval);
	    break;

	case IPMI_FRU_DATA_FLOAT:
	    ipmi_cmdlang_out(cmd_info, "Type", "float");
	    ipmi_cmdlang_out_double(cmd_info, "Data", floatval);
	    break;

	case IPMI_FRU_DATA_SUB_NODE:
	    if (intval == -1)
		ipmi_cmdlang_out(cmd_info, "Record", NULL);
	    else
		ipmi_cmdlang_out(cmd_info, "Array", NULL);
	    ipmi_cmdlang_down(cmd_info);
	    if (intval != -1)
		ipmi_cmdlang_out_int(cmd_info, "Element Count", intval);
	    traverse_fru_multi_record_tree(cmd_info, sub_node);
	    ipmi_cmdlang_up(cmd_info);
	    break;
	    
	default:
	    ipmi_cmdlang_out(cmd_info, "Type", "unknown");
	    break;
	}

	ipmi_cmdlang_up(cmd_info);
	if (data)
	    ipmi_fru_data_free(data);
    }
    
    ipmi_fru_put_node(node);

    return 0;
}

void
ipmi_cmdlang_dump_fru_info(ipmi_cmd_info_t *cmd_info, ipmi_fru_t *fru)
{
    ipmi_cmdlang_t            *cmdlang = ipmi_cmdinfo_get_cmdlang(cmd_info);
    int                       rv;
    int                       i;
    int                       num, onum;
    const char                *name;
    enum ipmi_fru_data_type_e dtype;
    int                       intval;
    time_t                    time;
    char                      *data;
    unsigned int              data_len;
    unsigned int              num_multi;
    char                      fru_name[IPMI_FRU_NAME_LEN];
    ipmi_fru_node_t           *node;

    ipmi_cmdlang_out(cmd_info, "FRU", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));
    ipmi_cmdlang_out(cmd_info, "Name", fru_name);

    num = 0;
    for (i=0; ;) {
	onum = num;
	data = NULL;
	rv = ipmi_fru_get(fru, i, &name, &num, &dtype, &intval, &time,
			  &data, &data_len);
	if (rv == EINVAL)
	    break;
	else if ((rv == ENOSYS) || (rv == E2BIG)) {
	    i++;
	    num = 0;
	    continue;
	} else if (rv) {
	    cmdlang->err = rv;
	    cmdlang->errstr = strerror(rv);
	    goto out_err;
	}

	ipmi_cmdlang_out(cmd_info, "Record", NULL);
	ipmi_cmdlang_down(cmd_info);
	ipmi_cmdlang_out(cmd_info, "Name", name);
	if (num != onum) {
	    ipmi_cmdlang_out_int(cmd_info, "Number", onum);
	    if (num == -1) {
		i++;
		num = 0;
	    }
	} else {
	    i++;
	    num = 0;
	}
	switch(dtype) {
	case IPMI_FRU_DATA_INT:
	    ipmi_cmdlang_out(cmd_info, "Type", "integer");
	    ipmi_cmdlang_out_int(cmd_info, "Data", intval);
	    break;

	case IPMI_FRU_DATA_TIME:
	    ipmi_cmdlang_out(cmd_info, "Type", "integer");
	    ipmi_cmdlang_out_long(cmd_info, "Data", (long) time);
	    break;

	case IPMI_FRU_DATA_BINARY:
	    ipmi_cmdlang_out(cmd_info, "Type", "binary");
	    ipmi_cmdlang_out_binary(cmd_info, "Data", data, data_len);
	    break;

	case IPMI_FRU_DATA_UNICODE:
	    ipmi_cmdlang_out(cmd_info, "Type", "unicode");
	    ipmi_cmdlang_out_unicode(cmd_info, "Data", data, data_len);
	    break;

	case IPMI_FRU_DATA_ASCII:
	    ipmi_cmdlang_out(cmd_info, "Type", "ascii");
	    ipmi_cmdlang_out(cmd_info, "Data", data);
	    break;

	case IPMI_FRU_DATA_BOOLEAN:
	    ipmi_cmdlang_out(cmd_info, "Type", "boolean");
	    ipmi_cmdlang_out_bool(cmd_info, "Data", intval);
	    break;

	default:
	    ipmi_cmdlang_out(cmd_info, "Type", "unknown");
	    break;
	}
	ipmi_cmdlang_up(cmd_info);

	if (data)
	    ipmi_fru_data_free(data);
    }

    num_multi = ipmi_fru_get_num_multi_records(fru);
    for (i=0; i<num_multi; i++) {
	unsigned char type, ver;
	unsigned int  len;
	char          *data = NULL;

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
	ipmi_cmdlang_out_int(cmd_info, "Type", type);
	ipmi_cmdlang_out_int(cmd_info, "Number", i);
	fru_out_data(cmd_info, IPMI_BINARY_STR, data, len);
	rv = ipmi_fru_multi_record_get_root_node(fru, i, &name, &node);
	if (!rv) {
	    ipmi_cmdlang_out(cmd_info, "Decode", NULL);
	    ipmi_cmdlang_down(cmd_info);
	    ipmi_cmdlang_out(cmd_info, "Name", name);
	    traverse_fru_multi_record_tree(cmd_info, node);
	    ipmi_cmdlang_up(cmd_info);
	}

	ipmi_cmdlang_up(cmd_info);
	ipmi_mem_free(data);
    }

 out_err:
    ipmi_cmdlang_up(cmd_info);
    if (cmdlang->err)
	cmdlang->location = "cmd_domain.c(dump_fru_info)";
}
