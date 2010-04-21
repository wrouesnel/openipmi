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
#include <limits.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_cmdlang.h>

/* Internal includes, do not use in your programs */
#include <OpenIPMI/internal/ipmi_malloc.h>

static int
traverse_fru_node_tree(ipmi_cmd_info_t *cmd_info,
		       ipmi_fru_node_t *node,
		       unsigned int    length)
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
    
    for (i=0; i<length; i++) {
	data = NULL;
        rv = ipmi_fru_node_get_field(node, i, &name, &dtype, &intval, &time,
				     &floatval, &data, &data_len, &sub_node);
        if (rv == EINVAL)
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
	    else
		intval = INT_MAX;
	    traverse_fru_node_tree(cmd_info, sub_node, intval);
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
    char                      fru_name[IPMI_FRU_NAME_LEN];
    ipmi_fru_node_t           *node;
    const char                *type;

    ipmi_cmdlang_out(cmd_info, "FRU", NULL);
    ipmi_cmdlang_down(cmd_info);
    ipmi_fru_get_name(fru, fru_name, sizeof(fru_name));
    ipmi_cmdlang_out(cmd_info, "Name", fru_name);

    rv = ipmi_fru_get_root_node(fru, &type, &node);
    if (!rv) {
	ipmi_cmdlang_out(cmd_info, "Type", type);
	rv = traverse_fru_node_tree(cmd_info, node, INT_MAX);
	if (rv)
	    cmdlang->errstr = "Error traversing FRU node tree";
    } else {
	cmdlang->errstr = "Error getting root node of FRU";
    }

    ipmi_cmdlang_up(cmd_info);
    if (rv) {
	cmdlang->err = rv;
	cmdlang->location = "cmd_domain.c(dump_fru_info)";
    }
}
