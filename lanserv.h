
#ifndef __LANSERV_H
#define __LANSERV_H

#include <sys/uio.h> /* for iovec */
#include <stdint.h>

#include <OpenIPMI/ipmi_auth.h>

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

    uint32_t      seq;
    uint32_t      sid;
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

    unsigned char *data;
    int           len;

    unsigned long ll_data; /* For use by the low-level code. */
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
    uint32_t        recv_seq;
    uint32_t        xmit_seq;
    uint32_t        sid;
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
    uint16_t      allowed_auths;

    /* Set by the user code. */
    int           idx; /* My idx in the table. */
} user_t;

typedef struct lan_data_s lan_data_t;
struct lan_data_s
{
    /* user 0 is not used. */
    user_t users[MAX_USERS+1];

    /* session 0 is not used. */
    session_t sessions[MAX_SESSIONS+1];

    channel_t channel;
    channel_t nonv_channel; /* What to write to nonv ram. */

    unsigned char *guid;


    void *user_info;

    void (*lan_send)(lan_data_t *lan,
		     struct iovec *data, int vecs,
		     void *addr, int addr_len);

    int (*smi_send)(lan_data_t *lan, msg_t *msg);

    /* Generate 'size' bytes of random data into 'data'. */
    void (*gen_rand)(lan_data_t *lan, void *data, int size);

    /* Allocate and free data. */
    void *(*alloc)(lan_data_t *lan, int size);
    void (*free)(lan_data_t *lan, void *data);

    /* Writethe configuration file (done when a non-volatile
       change is done, or when a user name/password is written. */
    void (*write_config)(lan_data_t *lan);


    /* Don't fill in the below in the user code. */

    /* Used to make the sid somewhat unique. */
    uint32_t sid_seq;

    unsigned int active_sessions;

    ipmi_authdata_t challenge_auth;
    unsigned int next_challenge_seq;
};


void handle_asf(lan_data_t *lan,
		unsigned char *data, int len,
		void *from_addr, int from_len);

void ipmi_handle_lan_msg(lan_data_t *lan,
			 unsigned char *data, int len,
			 void *from_addr, int from_len);

void ipmi_handle_smi_rsp(lan_data_t *len, msg_t *msg,
			 unsigned char *rsp, int rsp_len);

#endif /* __LANSERV_H */
