/*
 * fru_spd_decode.c
 *
 * IPMI code for handling FRU with SPD data
 *
 * Author: Novell Inc.
 *         Pat Campbell plc@novell.com
 *
 * Copyright 2005 Novell Inc.
 *
 * Corey Minyard: Removed the SPD-specific function calls and only
 * support the new FRU interface.
 * 
 * Copyright 2005 Montavista Software, Inc.
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

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <values.h>

#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_fru.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/internal/ipmi_fru.h>
#include <OpenIPMI/internal/ipmi_malloc.h>

#include "manfid.h"

/*
 * From PC SDRAM Serial Presence Detect (SPD) Specification
 * Revision 1.2A December, 1997 and
 *  http://www.simmtester.com/page/news/showpubnews.asp?num=101
 */
/* Used to decode byte 2, Memory Type, of SPD data */
static const struct valstr spd_memtype_vals[] = 
{
    {0x02, "EDO"},
    {0x04, "SDRAM"},
    {0x07, "DDR"},
    {0x00, NULL},
};

/* Used to decode byte 11, Module Configuration Type, of SPD data */
static const struct valstr spd_config_vals[] = 
{
    {0x00, "None"},
    {0x01, "Parity"},
    {0x02, "ECC"},
    {0x00, NULL},
};

/* Used to decode byte 8, Module Interface Signal Levels, of SPD data */
static const struct valstr spd_voltage_vals[] = 
{
    {0x00, "5.0V TTL"},
    {0x01, "LVTTL"},
    {0x02, "HSTL 1.5V"},
    {0x03, "SSTL 3.3V"},
    {0x04, "SSTL 2.5V"},
    {0x00, NULL},
};

typedef struct _SPDInfo
{
    int           size;
    const char    *memoryType;
    const char    *voltageInterface;
    const char    *errorDetection;
    const char    *manufacturer;
    char          partNumber[19];
    unsigned char rawData[128];
} SPD_info_t;


static void
fru_node_destroy (ipmi_fru_node_t *node)
{
    ipmi_fru_t *fru = _ipmi_fru_node_get_data(node);
    ipmi_fru_deref(fru);
}

static int
set_fru_str_info(const char                **name,
		 enum ipmi_fru_data_type_e *dtype,
		 char                      **data,
		 unsigned int              *data_len,
		 const char                *iname,
		 const char                *idata)
{
    int len = 0;
    if (name)
	*name = iname;
    if (dtype)
	*dtype = IPMI_FRU_DATA_ASCII;
    if (data) {
	char *d;
	len = strlen(idata) + 1;
	d = ipmi_mem_alloc(len);
	if (!d)
	    return ENOMEM;
	strcpy(d, idata);
	*data = d;
    }
    if (data_len) {
	if (!len)
	    len = strlen(idata) + 1;
	*data_len = len;
    }
    return 0;
}

static int
fru_node_get_field (ipmi_fru_node_t           *pnode,
		    unsigned int              index,
		    const char                **name,
		    enum ipmi_fru_data_type_e *dtype,
		    int                       *intval,
		    time_t                    *time,
		    double                    *floatval,
		    char                      **data,
		    unsigned int              *data_len,
		    ipmi_fru_node_t           **sub_node)
{
    ipmi_fru_t *fru = _ipmi_fru_node_get_data(pnode);
    SPD_info_t *spd_info = _ipmi_fru_get_rec_data(fru);
    int        rv;

    switch (index) {
    case 0:
	if (name)
	    *name = "size";
	if (intval)
	    *intval = spd_info->size;
	if (dtype)
	    *dtype = IPMI_FRU_DATA_INT;
	rv = 0;
	break;

    case 1:
	rv = set_fru_str_info(name, dtype, data, data_len, "memory_type",
			      spd_info->memoryType);
	break;

    case 2:
	rv = set_fru_str_info(name, dtype, data, data_len, "voltage_interface",
			      spd_info->voltageInterface);
	break;

    case 3:
	rv = set_fru_str_info(name, dtype, data, data_len, "error_detection",
			      spd_info->errorDetection);
	break;

    case 4:
	rv = set_fru_str_info(name, dtype, data, data_len, "manufacturer",
			      spd_info->manufacturer);
	break;

    case 5:
	rv = set_fru_str_info(name, dtype, data, data_len, "part_number",
			      spd_info->partNumber);
	break;

    default:
	rv = EINVAL;
    }

    return rv;
}


static int
fru_get_root_node (ipmi_fru_t *fru, const char **name, ipmi_fru_node_t **rnode)
{
    ipmi_fru_node_t *node;

    if (name)
	*name = "SPD FRU";
    if (rnode) {
	node = _ipmi_fru_node_alloc(fru);
	if (!node)
	    return ENOMEM;
	_ipmi_fru_node_set_data(node, fru);
	_ipmi_fru_node_set_get_field(node, fru_node_get_field);
	_ipmi_fru_node_set_destructor(node, fru_node_destroy);
	ipmi_fru_ref(fru);
	*rnode = node;
    }
    return 0;
}

static void
fru_cleanup_recs (ipmi_fru_t *fru)
{
    SPD_info_t *spd_info = (SPD_info_t *) _ipmi_fru_get_rec_data (fru);

    if (!spd_info)
	return;

    ipmi_mem_free(spd_info);
}


static const char *
val2str(uint16_t val, const struct valstr *vs)
{
    int i = 0;

    while (vs[i].str != NULL) {
	if (vs[i].val == val)
	    return vs[i].str;
	i++;
    }
    return NULL;
}

static void
loadInfo(SPD_info_t *spd_info, unsigned char *spd_data)
{
    int i;

    memcpy(spd_info->rawData, spd_data, 128);
    spd_info->size = spd_data[5] * (spd_data[31] << 2);
    spd_info->memoryType = val2str(spd_data[2], spd_memtype_vals);
    spd_info->voltageInterface = val2str(spd_data[8], spd_voltage_vals);
    spd_info->errorDetection = val2str(spd_data[11], spd_config_vals);

    /* handle jedec table bank continuation values */
    spd_info->manufacturer = NULL;
    if (spd_data[64] != 0x7f)
	spd_info->manufacturer = val2str (spd_data[64], jedec_id1_vals);
    else if (spd_data[65] != 0x7f)
	spd_info->manufacturer = val2str (spd_data[65], jedec_id2_vals);
    else if (spd_data[66] != 0x7f)
	spd_info->manufacturer = val2str (spd_data[66], jedec_id3_vals);
    else if (spd_data[67] != 0x7f)
	spd_info->manufacturer = val2str (spd_data[67], jedec_id4_vals);
    else if (spd_data[68] != 0x7f)
	spd_info->manufacturer = val2str (spd_data[68], jedec_id5_vals);
    else
	spd_info->manufacturer = val2str (spd_data[69], jedec_id6_vals);

    if (spd_info->manufacturer == NULL)
	spd_info->manufacturer = "Unknown";

    if (spd_data[73]) {
	for (i=0; i<18; i++) {
	    /* Some strings seem to use 0xff for filler. */
	    if (spd_data[73+i] == 0xff)
		break;
	    spd_info->partNumber[i] = spd_data[73+i];
	}
	spd_info->partNumber[i] = '\0';
    } else {
	strcpy(spd_info->partNumber, "Unknown");
    }
}

static int
process_fru_spd_info(ipmi_fru_t *fru)
{
    unsigned char *data = _ipmi_fru_get_data_ptr(fru);
    SPD_info_t    *spd_info;

    /*
     * We are here because FRU checksum failed
     *  ipmitool uses dev_type and dev_type_modifier
     *  to determine if it is an SPD.  ipmiutil uses
     *  first byte of 0x80, which is what we will use
     *  to start with
     */
    if (data[0] == 0x80) {
	_ipmi_fru_set_op_get_root_node(fru, fru_get_root_node);
	spd_info = ipmi_mem_alloc(sizeof (*spd_info));
	if (!spd_info)
	    return ENOMEM;
	memset(spd_info, 0, sizeof(*spd_info));
	loadInfo(spd_info, data);
	_ipmi_fru_set_rec_data(fru, spd_info);
	_ipmi_fru_set_op_cleanup_recs(fru, fru_cleanup_recs);
	return 0;
    }
    return EBADF;
}

/************************************************************************
 *
 * Init/shutdown
 *
 ************************************************************************/

static int spd_initialized;

int
_ipmi_fru_spd_decoder_init (void)
{
    int rv;

    if (spd_initialized)
	return 0;

    rv = _ipmi_fru_register_decoder (process_fru_spd_info);
    if (!rv)
	spd_initialized = 1;
    return rv;
}

void
_ipmi_fru_spd_decoder_shutdown (void)
{
    if (!spd_initialized)
	return;
    _ipmi_fru_deregister_decoder (process_fru_spd_info);
    spd_initialized = 0;
}
