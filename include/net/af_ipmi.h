/* 
 * IPMI Socket Glue
 *
 * Author:	Louis Zhuang <louis.zhuang@linux.intel.com>
 * Copyright by Intel Corp., 2003
 */
#ifndef _NET_IPMI_H
#define _NET_IPMI_H

#include <linux/ipmi.h>

#ifndef AF_IPMI
#define AF_IPMI		32
#endif
#ifndef PF_IPMI
#define PF_IPMI		AF_IPMI
#endif

/*
 * This is ipmi address for socket
 */
struct sockaddr_ipmi {
	sa_family_t      sipmi_family; /* AF_IPMI */
	int              if_num; /* IPMI interface number */
	struct ipmi_addr ipmi_addr;
};
#define SOCKADDR_IPMI_OVERHEAD (sizeof(struct sockaddr_ipmi) \
				- sizeof(struct ipmi_addr))

/* A msg_control item, this takes a 'struct ipmi_timing_parms' */
#define IPMI_CMSG_TIMING_PARMS	0x01

/* 
 * This is ipmi message for socket
 */
struct ipmi_sock_msg {
	int                   recv_type;
	long                  msgid;

	unsigned char         netfn;
	unsigned char         cmd;
	int                   data_len;
	unsigned char         data[0];
};

#define IPMI_MAX_SOCK_MSG_LENGTH (sizeof(struct ipmi_sock_msg)+IPMI_MAX_MSG_LENGTH)

/* Register/unregister to receive specific commands.  Uses struct
   ipmi_cmdspec from linux/ipmi.h */
#define SIOCIPMIREGCMD		(SIOCPROTOPRIVATE + 0)
#define SIOCIPMIUNREGCMD	(SIOCPROTOPRIVATE + 1)

/* Register to receive events.  Takes an integer */
#define SIOCIPMIGETEVENT	(SIOCPROTOPRIVATE + 2)

/* Set the default timing parameters for the socket.  Takes a struct
   ipmi_timing_parms from linux/ipmi.h */
#define SIOCIPMISETTIMING	(SIOCPROTOPRIVATE + 3)
#define SIOCIPMIGETTIMING	(SIOCPROTOPRIVATE + 4)

/* Set/Get the IPMB address of the MC we are connected to, takes an
   unsigned int. */
#define SIOCIPMISETADDR		(SIOCPROTOPRIVATE + 5)
#define SIOCIPMIGETADDR		(SIOCPROTOPRIVATE + 6)

#endif/*_NET_IPMI_H*/
