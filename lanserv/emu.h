
#ifndef __EMU_IPMI_
#define __EMU_IPMI_

#include <OpenIPMI/ipmi_types.h>

typedef struct emu_data_s emu_data_t;

/* These are so the sub-processing code can override these parameters
   in the return msg. */
typedef struct emu_msgparms_s
{
    unsigned char *netfn;
    unsigned char *rqSA;
    unsigned char *seq;
    unsigned char *rqLun;
    unsigned char *cmd;
} emu_msgparms_t;

emu_data_t *ipmi_emu_alloc(void);

void ipmi_emu_handle_msg(emu_data_t     *emu,
			 emu_msgparms_t *parms,
			 unsigned char  lun,
			 ipmi_msg_t     *msg,
			 unsigned char  *rdata,
			 unsigned int   *rdata_len);

void ipmi_emu_register_ipmb(emu_data_t    *emu,
			    unsigned char slave_addr,
			    emu_data_t    *semu);

#endif /* __EMU_IPMI_ */
