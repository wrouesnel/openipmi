
#ifndef __LANSERV_H
#define __LANSERV_H

#include <OpenIPMI/ipmi_types.h>
#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_addr.h>

#define IPMI_MAX_LAN_LEN (IPMI_MAX_MSG_LENGTH + 42 + 7)

/*
 * Restrictions: <=64 sessions
 *               <=64 users (per spec, 6 bits)
 */
#define MAX_USERS		63
#define USER_BITS_REQ		6 /* Bits required to hold a user. */
#define USER_MASK		0x3f
#define MAX_SESSIONS		63
#define SESSION_BITS_REQ	6 /* Bits required to hold a session. */
#define SESSION_MASK		0x3f

#define MAIN_CHANNEL	0x7

typedef struct msg_s
{
    void *src_addr;
    int  src_len;

    unsigned int  seq;
    unsigned int  sid;
    unsigned char *authcode;
    unsigned char authcode_data[16];
    unsigned char authtype;

    unsigned char netfn;
    unsigned char rs_addr;
    unsigned char rs_lun;
    unsigned char rq_addr;
    unsigned char rq_lun;
    unsigned char rq_seq;
    unsigned char cmd;

    unsigned char data[IPMI_MAX_MSG_LENGTH];
    int           len;
} msg_t;

#define NUM_PRIV_LEVEL 4
typedef struct channel_s
{
    unsigned int available : 1;

    unsigned int PEF_alerting : 1;
    unsigned int per_msg_auth : 1;

    /* We don't support user-level authentication disable, and access
       mode is always available and cannot be set. */

    unsigned int priviledge_limit : 4;
    struct {
	unsigned char allowed_auths;
    } priv_info[NUM_PRIV_LEVEL];
} channel_t;

typedef struct session_s
{
    unsigned int active : 1;

    int           idx; /* My idx in the table. */

    unsigned char   authtype;
    ipmi_authdata_t authdata;
    unsigned int    recv_seq;
    unsigned int    xmit_seq;
    unsigned int    sid;
    unsigned char   userid;

    unsigned char priv;
    unsigned char max_priv;
} session_t;

typedef struct user_s
{
    unsigned char valid;
    unsigned char username[16];
    unsigned char pw[16];
    unsigned char priviledge;
    unsigned char max_sessions;
    unsigned char curr_sessions;
    unsigned int  allowed_auths;

    /* Set by the user code. */
    int           idx; /* My idx in the table. */
} user_t;

typedef struct lan_data_s
{
    /* user 0 is not used. */
    user_t users[MAX_USERS+1];

    /* session 0 is not used. */
    session_t sessions[MAX_SESSIONS+1];

    channel_t channel;
    channel_t nonv_channel; /* What to write to nonv ram. */

    unsigned char *guid;


    void *lan_info;
    void (*lan_send)(void *lan_info, unsigned char *data, int len,
		     void *addr, int addr_len);

    void *smi_info;
    int (*smi_send)(void *smi, ipmi_msg_t *msg,
		    void *cb_data, ipmi_addr_t *addr, int addr_len);

    /* Generate 'size' bytes of random data into 'data'. */
    void (*gen_rand)(void *data, int size);

    /* Allocate and free data. */
    void *(*alloc)(int size);
    void (*free)(void *data);

    /* Writethe configuration file (done when a non-volatile
       change is done, or when a user name/password is written. */
    void *config_info;
    void (*write_config)(void *config_info, struct lan_data_s *data);

    /* Don't fill in the below in the user code. */

    /* Used to make the sid somewhat unique. */
    unsigned int sid_seq;

    unsigned int active_sessions;

    ipmi_authdata_t challenge_auth;
    unsigned int next_challenge_seq;
} lan_data_t;


void ipmi_handle_lan_msg(lan_data_t *lan,
			 unsigned char *data, int len,
			 void *from_addr, int from_len);

void ipmi_handle_smi_msg(lan_data_t  *len,
			 ipmi_addr_t *addr,
			 ipmi_msg_t  *imsg,
			 void        *cb_data);

#endif /* __LANSERV_H */
