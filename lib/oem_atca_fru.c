/*
 * oem_atca_fru.c
 *
 * FRU Multirecord decoding for ATCA multirecords.
 *
 *  (C) 2005 MontaVista Software, Inc.
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

#include <string.h>
#include <stdio.h> /* for sprintf */
#include <OpenIPMI/internal/ipmi_fru.h>
#include <OpenIPMI/internal/ipmi_int.h>

/***********************************************************************
 *
 * Point-to-point connectivity record
 *
 **********************************************************************/

static ipmi_mr_item_layout_t p2p_cr_desc_ent_items[] = {
    { .name = "remote slot", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 8,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "remote channel", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 8, .length = 5,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "local channel ", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 13, .length = 5,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field }
};
static ipmi_mr_struct_layout_t p2p_cr_desc_ent = {
    .name = NULL, .length = 3,
    .item_count = 3, .items = p2p_cr_desc_ent_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_item_layout_t p2p_cr_desc_items[] = {
    { .name = "channel type", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "slot address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_array_layout_t p2p_cr_desc_arys[] = {
    { .name = "channels", .has_count = 1, .min_elem_size = 3, .settable = 1,
      .elem_layout = &p2p_cr_desc_ent,
      .elem_check = ipmi_mr_struct_elem_check,
      .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t p2p_cr_desc = {
    .name = NULL, .length = 2,
    .item_count = 2, .items = p2p_cr_desc_items,
    .array_count = 1, .arrays = p2p_cr_desc_arys,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_item_layout_t p2p_cr_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_array_layout_t p2p_cr_arys[] = {
    { .name = "descriptors", .has_count = 0, .min_elem_size = 3, .settable = 1,
      .elem_layout = &p2p_cr_desc,
      .elem_check = ipmi_mr_struct_elem_check, .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t p2p_cr = {
    .name = "Point-to-Point Connectivity Record", .length = 1,
    .item_count = 1, .items = p2p_cr_items,
    .array_count = 1, .arrays = p2p_cr_arys,
    .cleanup = ipmi_mr_struct_cleanup
};


/***********************************************************************
 *
 * Address table descriptor record
 *
 **********************************************************************/

static ipmi_mr_item_layout_t addr_tab_ent[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "site_number", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "site_type", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 2, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_struct_layout_t addr_tab_ents = {
    .name = NULL, .length = 3,
    .item_count = 3, .items = addr_tab_ent,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_item_layout_t addr_tab_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = ipmi_mr_int_get_field },
    { .name = "shelf address", .dtype = IPMI_FRU_DATA_ASCII, .settable = 1,
      .start = 1, .length = 21,
      .set_field = ipmi_mr_str_set_field, .get_field = ipmi_mr_str_get_field },
};
static ipmi_mr_array_layout_t addr_tab_arys[] = {
    { .name = "addresses", .has_count = 1, .min_elem_size = 3, .settable = 1,
      .elem_layout = &addr_tab_ents,
      .elem_check = ipmi_mr_struct_elem_check, .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t addr_tab = {
    .name = "Address Table", .length = 22,
    .item_count = 2, .items = addr_tab_items,
    .array_count = 1, .arrays = addr_tab_arys,
    .cleanup = ipmi_mr_struct_cleanup
};


/***********************************************************************
 *
 * Shelf power distribution record
 *
 **********************************************************************/

static ipmi_mr_item_layout_t pow_dist_f2f_items[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "FRU device id", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_struct_layout_t pow_dist_f2f = {
    .name = NULL, .length = 2,
    .item_count = 2, .items = pow_dist_f2f_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_item_layout_t pow_dist_maps_items[] = {
    { .name = "max extern avail current", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 0, .length = 2,
      .u = { .multiplier = 0.1 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "max internal current", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 2, .length = 2,
      .u = { .multiplier = 0.1 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field },
    { .name = "min operating voltage", .dtype = IPMI_FRU_DATA_FLOAT,
      .settable = 1,
      .start = 2, .length = 2,
      .u = { .multiplier = 0.5 },
      .set_field = ipmi_mr_intfloat_set_field,
      .get_field = ipmi_mr_intfloat_get_field }
};
static ipmi_mr_array_layout_t pow_dist_maps_arys[] = {
    { .name = "feed to frus", .has_count = 1, .min_elem_size = 6,
      .settable = 1,
      .elem_layout = &pow_dist_f2f,
      .elem_check = ipmi_mr_struct_elem_check,
      .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t pow_dist_maps = {
    .name = NULL, .length = 5,
    .item_count = 3, .items = pow_dist_maps_items,
    .array_count = 1, .arrays = pow_dist_maps_arys,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_item_layout_t pow_dist_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_array_layout_t pow_dist_arys[] = {
    { .name = "power feeds", .has_count = 1, .min_elem_size = 3, .settable = 1,
      .elem_layout = &pow_dist_maps,
      .elem_check = ipmi_mr_struct_elem_check,
      .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t pow_dist = {
    .name = "Shelf Power Distribution", .length = 1,
    .item_count = 1, .items = pow_dist_items,
    .array_count = 1, .arrays = pow_dist_arys,
    .cleanup = ipmi_mr_struct_cleanup
};


/***********************************************************************
 *
 * Shelf activation and power management record
 *
 **********************************************************************/

static ipmi_mr_item_layout_t act_pm_desc[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "FRU device id", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "max FRU power", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 2, .length = 2,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "shelf manager activation", .dtype = IPMI_FRU_DATA_BOOLEAN,
      .settable = 1,
      .start = 38, .length = 1,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "delay before next power on", .dtype = IPMI_FRU_DATA_INT,
      .settable = 1,
      .start = 32, .length = 6,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field }
};
static ipmi_mr_struct_layout_t act_pm_descs = {
    .name = NULL, .length = 5,
    .item_count = 5, .items = act_pm_desc,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_item_layout_t act_pm_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = ipmi_mr_int_get_field },
    { .name = "allowance for activation readiness", .dtype = IPMI_FRU_DATA_INT,
      .settable = 1,
      .start = 1, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_array_layout_t act_pm_arys[] = {
    { .name = "activation power descriptors", .has_count = 1, .settable = 1,
      .min_elem_size = 5,
      .elem_layout = &act_pm_descs,
      .elem_check = ipmi_mr_struct_elem_check, .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t act_pm = {
    .name = "Shelf Activation and Power Management", .length = 2,
    .item_count = 1, .items = act_pm_items,
    .array_count = 1, .arrays = act_pm_arys,
    .cleanup = ipmi_mr_struct_cleanup
};


/***********************************************************************
 *
 * Shelf manager IP connection record
 *
 **********************************************************************/

static ipmi_mr_item_layout_t ip_conn0_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = ipmi_mr_int_get_field },
    { .name = "ip address", .dtype = IPMI_FRU_DATA_ASCII,
      .settable = 1,
      .start = 1, .length = 4,
      .set_field = ipmi_mr_ip_set_field, .get_field = ipmi_mr_ip_get_field }
};
static ipmi_mr_struct_layout_t ip_conn0 = {
    .name = "Shelf Manager IP Connection", .length = 5,
    .item_count = 2, .items = ip_conn0_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};

static ipmi_mr_item_layout_t ip_conn1_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = ipmi_mr_int_get_field },
    { .name = "ip address", .dtype = IPMI_FRU_DATA_ASCII,
      .settable = 1,
      .start = 1, .length = 4,
      .set_field = ipmi_mr_ip_set_field, .get_field = ipmi_mr_ip_get_field },
    { .name = "gateway address", .dtype = IPMI_FRU_DATA_ASCII,
      .settable = 1,
      .start = 5, .length = 4,
      .set_field = ipmi_mr_ip_set_field, .get_field = ipmi_mr_ip_get_field },
    { .name = "subnet mask", .dtype = IPMI_FRU_DATA_ASCII,
      .settable = 1,
      .start = 9, .length = 4,
      .set_field = ipmi_mr_ip_set_field, .get_field = ipmi_mr_ip_get_field }
};
static ipmi_mr_struct_layout_t ip_conn1 = {
    .name = "Shelf Manager IP Connection", .length = 13,
    .item_count = 4, .items = ip_conn1_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};

static int
atca_root_ipmi_mr_shelf_mgr_ip_conn(ipmi_fru_t          *fru,
			       unsigned int        mr_rec_num,
			       unsigned char       *mr_data,
			       unsigned int        mr_data_len,
			       const char          **name,
			       ipmi_fru_node_t     **node)
{
    ipmi_mr_struct_layout_t *layout;

    if (mr_data_len < 5)
	return EINVAL;
    switch (mr_data[4]) {
    case 0: layout = &ip_conn0; break;
    case 1: layout = &ip_conn1; break;
    default:
	return EINVAL;
    }
    return ipmi_mr_struct_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
			       layout, name, node);
}

/***********************************************************************
 *
 * Board point-to-point Connectivity record
 *
 **********************************************************************/

static ipmi_mr_item_layout_t guid_elem = {
    .name = "GUID", .dtype = IPMI_FRU_DATA_BINARY, .settable = 1,
    .start = 0, .length = 16,
    .set_field = ipmi_mr_binary_set_field,
    .get_field = ipmi_mr_binary_get_field
};
static ipmi_mr_tab_item_t link_if_tab = {
    .count = 3,
    .table = { "base", "fabric", "update channel" }
};
static ipmi_mr_item_layout_t link_desc[] = {
    { .name = "link grouping id", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 24, .length = 8,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "link type extension", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 20, .length = 4,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "link type", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 12, .length = 8,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "port 3 included", .dtype = IPMI_FRU_DATA_BOOLEAN, .settable = 1,
      .start = 11, .length = 1,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "port 2 included", .dtype = IPMI_FRU_DATA_BOOLEAN, .settable = 1,
      .start = 10, .length = 1,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "port 1 included", .dtype = IPMI_FRU_DATA_BOOLEAN, .settable = 1,
      .start = 9, .length = 1,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "port 0 included", .dtype = IPMI_FRU_DATA_BOOLEAN, .settable = 1,
      .start = 8, .length = 1,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field },
    { .name = "interface", .dtype = IPMI_FRU_DATA_ASCII, .settable = 1,
      .start = 6, .length = 2,
      .u = { .tab_data = &link_if_tab },
      .set_field = ipmi_mr_bitvaltab_set_field,
      .get_field = ipmi_mr_bitvaltab_get_field,
      .get_enum  = ipmi_mr_bitvaltab_get_enum },
    { .name = "channel number", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 6,
      .set_field = ipmi_mr_bitint_set_field, .get_field = ipmi_mr_bitint_get_field }
};
static ipmi_mr_struct_layout_t link_descs = {
    .name = NULL, .length = 4,
    .item_count = 9, .items = link_desc,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_item_layout_t bp2p_conn_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_array_layout_t bp2p_conn_arys[] = {
    { .name = "OEM GUIDs", .has_count = 1, .settable = 1,
      .min_elem_size = 16,
      .elem_layout = &guid_elem,
      .elem_check = ipmi_mr_item_elem_check,
      .elem_decode = ipmi_mr_item_decode,
      .cleanup = ipmi_mr_item_array_cleanup,
      .get_field = ipmi_mr_item_array_get_field,
      .set_field = ipmi_mr_item_array_set_field },
    { .name = "Link Descriptors", .has_count = 0,
      .min_elem_size = 4,
      .elem_layout = &link_descs,
      .elem_check = ipmi_mr_struct_elem_check,
      .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t bp2p_conn = {
    .name = "Board P2P Connectivity", .length = 1,
    .item_count = 1, .items = bp2p_conn_items,
    .array_count = 2, .arrays = bp2p_conn_arys,
    .cleanup = ipmi_mr_struct_cleanup
};


/***********************************************************************
 *
 * Radial IPMB-0 Link Mapping
 *
 **********************************************************************/

static ipmi_mr_item_layout_t ipmb_link_mapping[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "IPMB-0 link entry", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_struct_layout_t ipmb_link_mappings = {
    .name = NULL, .length = 2,
    .item_count = 2, .items = ipmb_link_mapping,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_tab_item_t hub_info_if_tab = {
    .count = 4,
    .table = { NULL, "IPMB-A only", "IPMB-B only", "IPMB-A and IPMB-B" }
};
static ipmi_mr_item_layout_t hub_desc_items[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "bus coverage", .dtype = IPMI_FRU_DATA_ASCII, .settable = 1,
      .start = 8, .length = 2,
      .u = { .tab_data = &hub_info_if_tab },
      .set_field = ipmi_mr_bitvaltab_set_field,
      .get_field = ipmi_mr_bitvaltab_get_field,
      .get_enum  = ipmi_mr_bitvaltab_get_enum }
};
static ipmi_mr_array_layout_t hub_desc_arys[] = {
    { .name = "IPMB-0 link mappings", .has_count = 1, .settable = 1,
      .min_elem_size = 4,
      .elem_layout = &ipmb_link_mappings,
      .elem_check = ipmi_mr_struct_elem_check,
      .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t hub_descs = {
    .name = NULL, .length = 2,
    .item_count = 2, .items = hub_desc_items,
    .array_count = 1, .arrays = hub_desc_arys,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_item_layout_t rad_ipmb_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = ipmi_mr_int_get_field },
    { .name = "connecter definer", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 3,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "connecter version", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 4, .length = 2,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_array_layout_t rad_ipmb_arys[] = {
    { .name = "hub descriptors", .has_count = 1, .settable = 1,
      .min_elem_size = 4,
      .elem_layout = &hub_descs,
      .elem_check = ipmi_mr_struct_elem_check,
      .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t rad_ipmb = {
    .name = "Radial IPMB-0 Link Mapping", .length = 6,
    .item_count = 3, .items = rad_ipmb_items,
    .array_count = 1, .arrays = rad_ipmb_arys,
    .cleanup = ipmi_mr_struct_cleanup
};

/***********************************************************************
 *
 * Shelf fan geography record
 *
 **********************************************************************/

static ipmi_mr_item_layout_t fan_to_frus_items[] = {
    { .name = "hardware address", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 0, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "FRU device id", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 1, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "site number", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 2, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field },
    { .name = "site type", .dtype = IPMI_FRU_DATA_INT, .settable = 1,
      .start = 3, .length = 1,
      .set_field = ipmi_mr_int_set_field, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_struct_layout_t fan_to_frus = {
    .name = NULL, .length = 4,
    .item_count = 4, .items = fan_to_frus_items,
    .array_count = 0, .arrays = NULL,
    .cleanup = ipmi_mr_struct_cleanup
};
static ipmi_mr_item_layout_t fan_geog_items[] = {
    { .name = "version", .dtype = IPMI_FRU_DATA_INT, .settable = 0,
      .start = 0, .length = 1,
      .set_field = NULL, .get_field = ipmi_mr_int_get_field }
};
static ipmi_mr_array_layout_t fan_geog_arys[] = {
    { .name = "fan to frus", .has_count = 1, .settable = 1,
      .min_elem_size = 4,
      .elem_layout = &fan_to_frus,
      .elem_check = ipmi_mr_struct_elem_check,
      .elem_decode = ipmi_mr_struct_decode,
      .cleanup = ipmi_mr_struct_array_cleanup,
      .get_field = ipmi_mr_struct_array_get_field,
      .set_field = ipmi_mr_struct_array_set_field }
};
static ipmi_mr_struct_layout_t fan_geog = {
    .name = "Shelf Fan Geography", .length = 1,
    .item_count = 1, .items = fan_geog_items,
    .array_count = 1, .arrays = fan_geog_arys,
    .cleanup = ipmi_mr_struct_cleanup
};


/***********************************************************************
 *
 * Initialization code
 *
 **********************************************************************/

int
_ipmi_atca_fru_get_mr_root(ipmi_fru_t      *fru,
			   unsigned int    mr_rec_num,
			   unsigned int    manufacturer_id,
			   unsigned char   record_type_id,
			   unsigned char   *mr_data,
			   unsigned int    mr_data_len,
			   void            *cb_data,
			   const char      **name,
			   ipmi_fru_node_t **node)
{
    /* A record type and version number. */
    if (mr_data_len < 5)
	return EINVAL;

    switch (mr_data[3]) {
    case 4: /* backplane point-to-point connectivity record */
	if (mr_data[4] != 0)
	    return EINVAL;
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
				   &p2p_cr,
				   name, node);

    case 0x10: /* shelf address table */
	if (mr_data[4] != 0)
	    return EINVAL;
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
				   &addr_tab,
				   name, node);

    case 0x11: /* Shelf power distribution */
	if (mr_data[4] != 0)
	    return EINVAL;
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
				   &pow_dist,
				   name, node);

    case 0x12: /* Shelf activation and power mgmt */
	if (mr_data[4] != 0)
	    return EINVAL;
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
				   &act_pm,
				   name, node);

    case 0x13: /* Shelf Manager IP Connection Record */
	return atca_root_ipmi_mr_shelf_mgr_ip_conn(fru, mr_rec_num,
						   mr_data, mr_data_len,
						   name, node);

    case 0x14: /* Board p2p connectivity record */
	if (mr_data[4] != 0)
	    return EINVAL;
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
				   &bp2p_conn,
				   name, node);

    case 0x15: /* radial ipmb0 link mapping */
	if (mr_data[4] != 0)
	    return EINVAL;
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
				   &rad_ipmb,
				   name, node);

    case 0x1b: /* Shelf fan geography record */
	if (mr_data[4] != 0)
	    return EINVAL;
	return ipmi_mr_struct_root(fru, mr_rec_num, mr_data+4, mr_data_len-4,
				   &fan_geog,
				   name, node);

    default:
	return ENOSYS;
    }
}
