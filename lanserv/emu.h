
#ifndef __EMU_IPMI_
#define __EMU_IPMI_

#include <OpenIPMI/ipmi_types.h>

typedef struct emu_data_s emu_data_t;
typedef struct lmc_data_s lmc_data_t;

emu_data_t *ipmi_emu_alloc(void);

void ipmi_emu_handle_msg(emu_data_t     *emu,
			 unsigned char  lun,
			 ipmi_msg_t     *msg,
			 unsigned char  *rdata,
			 unsigned int   *rdata_len);

int ipmi_emu_add_mc(emu_data_t    *emu,
		    unsigned char ipmb,
		    unsigned char device_id,
		    unsigned char has_device_sdrs,
		    unsigned char device_revision,
		    unsigned char major_fw_rev,
		    unsigned char minor_fw_rev,
		    unsigned char device_support,
		    unsigned char mfg_id[3],
		    unsigned char product_id[2]);
int ipmi_emu_set_bmc_mc(emu_data_t *emu, unsigned char ipmb);

int ipmi_emu_get_mc_by_addr(emu_data_t    *emu,
			    unsigned char ipmb,
			    lmc_data_t    **mc);

int ipmi_mc_enable_sel(lmc_data_t    *emu,
		       int           max_entries,
		       unsigned char flags);
int ipmi_mc_add_to_sel(lmc_data_t    *emu,
		       unsigned char record_type,
		       unsigned char event[13]);

void ipmi_emu_set_device_id(lmc_data_t *emu, unsigned char device_id);
unsigned char ipmi_emu_get_device_id(lmc_data_t *emu);
void ipmi_set_has_device_sdrs(lmc_data_t *emu, unsigned char has_device_sdrs);
unsigned char ipmi_get_has_device_sdrs(lmc_data_t *emu);
void ipmi_set_device_revision(lmc_data_t *emu, unsigned char device_revision);
unsigned char ipmi_get_device_revision(lmc_data_t *emu);
void ipmi_set_major_fw_rev(lmc_data_t *emu, unsigned char major_fw_rev);
unsigned char ipmi_get_major_fw_rev(lmc_data_t *emu);
void ipmi_set_minor_fw_rev(lmc_data_t *emu, unsigned char minor_fw_rev);
unsigned char ipmi_get_minor_fw_rev(lmc_data_t *emu);
void ipmi_set_device_support(lmc_data_t *emu, unsigned char device_support);
unsigned char ipmi_get_device_support(lmc_data_t *emu);
void ipmi_set_mfg_id(lmc_data_t *emu, unsigned char mfg_id[3]);
void ipmi_get_mfg_id(lmc_data_t *emu, unsigned char mfg_id[3]);
void ipmi_set_product_id(lmc_data_t *emu, unsigned char product_id[3]);
void ipmi_get_product_id(lmc_data_t *emu, unsigned char product_id[3]);

void ipmi_emu_shutdown(void);
void ipmi_emu_cmd(emu_data_t *emu, char *cmd_str);

#endif /* __EMU_IPMI_ */
