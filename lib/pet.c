/*
 * pet.c
 *
 * MontaVista IPMI code handling for setting up and receiving platform
 * event traps.
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

/* NOTE: This code requires scan_sysaddr to be set for the BMC
   connections. */

#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_int.h>
#include <OpenIPMI/ipmi_pet.h>
#include <OpenIPMI/ipmi_pef.h>
#include <OpenIPMI/ipmi_lanparm.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_domain.h>

/* Recheck the PET config every 10 minutes. */
#define PET_TIMEOUT_SEC 600

static ipmi_rwlock_t  *pet_lock = NULL;
static os_hnd_fd_id_t *pet_wait_id = NULL;
static int            pet_fd = -1;

/* This data structure defines a data/mask setting for a parameter,
   either from the LAN or PEF parms. */
typedef struct parm_check_s
{
    unsigned char conf_num; /* The number we are interested in. */
    unsigned char set;      /* The specific selector. */
    unsigned char data_len; /* The length of the data we are using. */
    unsigned char data[22]; /* The actual data. */
    unsigned char mask[22]; /* The mask bits used to mask what we compare. */
} parm_check_t;

/* Information for running the timer.  Note that there is no lock in
   the timer, since the timer is only deleted when the pet_lock is
   held write, we read-lock the pet timer to avoid locking problem. */
typedef struct pet_timer_s {
    int          cancelled;
    os_handler_t *os_hnd;
    ipmi_pet_t   *pet;
    int          err;
} pet_timer_t;

/* A generic data item used for callbacks.  This is used for all
   configuration callbacks because the channel is important. */
typedef struct got_data_s
{
    unsigned int channel;
    int          err;
    ipmi_pet_t   *pet;
} got_data_t;

#define NUM_PEF_SETTINGS 4
#define NUM_LANPARM_SETTINGS 2

struct ipmi_pet_s
{
    int destroyed;

    /* Configuration parameters */
    ipmi_domain_id_t domain;
    struct in_addr   ip_addr;
    unsigned int     eft_sel;
    unsigned int     apt_sel;
    unsigned int     lan_dest_sel;

    /* The domain's OS handler */
    os_handler_t     *os_hnd;

    ipmi_pet_done_cb done;
    void             *cb_data;

    ipmi_pet_done_cb destroy_done;
    void             *destroy_cb_data;

    ipmi_lock_t      *lock;

    int              in_progress;

    got_data_t       got_data[IPMI_SELF_CHANNEL];

    /* Current LAN parameters we are working on.  We have one per
       possible channel that we can be configuring.  Since we can have
       more than one BMC that we hook to in a domain, we have to be
       able to configure each one.  We also run all the configuration
       checks simultaneously.  */
    int              lanparm_check_pos[IPMI_SELF_CHANNEL];
    ipmi_lanparm_t   *working_lanparm[IPMI_SELF_CHANNEL];

    /* The LAN configuration parameters are the same for every BMC
       that we hook to, so we only need one. */
    parm_check_t     lanparm_check[NUM_LANPARM_SETTINGS];

    /* Current PEF parameters, like the LAN parameters we do them all
       at once.  We also do them simultaneously (with the LAN
       parameters and with each other). */
    int              pef_check_pos[IPMI_SELF_CHANNEL];
    ipmi_pef_t       *working_pef[IPMI_SELF_CHANNEL];

    /* The PEF configuration parameters are mostly the same for every
       BMC, except for the channel which may vary from BMC to BMC. */
    unsigned char    channel[IPMI_SELF_CHANNEL];
    parm_check_t     pef_check[NUM_PEF_SETTINGS];

    /* Timer to check the configuration periodically. */
    pet_timer_t       *timer_info;
    os_hnd_timer_id_t *timer;

    /* Used so we know when MCs are added and can check to see if we
       need to scan them. */
    ipmi_domain_mc_upd_t *mc_upd;

    ipmi_pet_t       *next;
    ipmi_pet_t       *prev;
};

/* The list head. */
static ipmi_pet_t pet_list =
{
    .next = &pet_list,
    .prev = &pet_list
};

static void rescan_pet(void *cb_data, os_hnd_timer_id_t *id);

static void pet_handler(int fd, void *cb_data, os_hnd_fd_id_t *id)
{
}

static int
open_pet_socket(void)
{
    os_handler_t       *handler;
    struct sockaddr_in *paddr;
    struct sockaddr_in addr;
    int                err;

    if (pet_fd != -1)
	return 0;

    handler = ipmi_get_global_os_handler();

    pet_fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (pet_fd == -1) {
	err = errno;
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Unable to open PET UDP socket: 0x%x\n", err);
	goto out_err;
    }

    paddr = (struct sockaddr_in *)&addr;
    paddr->sin_family = AF_INET;
    paddr->sin_port = htons(162);
    paddr->sin_addr.s_addr = INADDR_ANY;

    err = bind(pet_fd, (struct sockaddr *) &addr, sizeof(addr));
    if (err == -1)
    {
	err = errno;
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Unable to bind PET UDP port: 0x%x\n", err);
	goto out_err;
    }

    err = handler->add_fd_to_wait_for(handler,
				      pet_fd,
				      pet_handler,
				      NULL,
				      &pet_wait_id);
    if (err) {
	ipmi_log(IPMI_LOG_ERR_INFO,
		 "Unable to add PET UDP handler: 0x%x\n", err);
	goto out_err;
    }

    return 0;

 out_err:
    if (pet_wait_id != NULL)
	handler->remove_fd_to_wait_for(handler, pet_wait_id);
    pet_wait_id = NULL;
    if (pet_fd != -1)
	close(pet_fd);
    pet_fd = -1;
    if (err == 0)
	return EINVAL;
    else
	return err;
}

static void
shutdown_pet_fd(void)
{
    os_handler_t *handler;

    if (pet_list.next != &pet_list)
	/* List is not empty, let the fd exist. */
	return;

    if (pet_wait_id) {
	handler = ipmi_get_global_os_handler();
	handler->remove_fd_to_wait_for(handler, pet_wait_id);
	pet_wait_id = NULL;
    }
    if (pet_fd != -1) {
	close(pet_fd);
	pet_fd = -1;
    }
}

static void
internal_pet_destroy(ipmi_pet_t *pet)
{
    /* Eventually, we could disable the PET entries, but the PEF
       entries are possibley shared, and there doesn't seem to be any
       way to disable the LAN entry. */
    ipmi_unlock(pet->lock);
    ipmi_destroy_lock(pet->lock);
    ipmi_mem_free(pet);
}

/* Must be called locked, this will unlock the PET. */
static void
pet_op_done(ipmi_pet_t *pet)
{
    struct timeval timeout;
    int            i;
    os_handler_t   *os_hnd = pet->os_hnd;

    pet->in_progress--;

    if (pet->in_progress == 0) {
	for (i=0; i<IPMI_SELF_CHANNEL; i++) {
	    if (pet->working_pef[i])
		ipmi_pef_destroy(pet->working_pef[i], NULL, NULL);
	    if (pet->working_lanparm[i])
		ipmi_lanparm_destroy(pet->working_lanparm[i], NULL, NULL);
	}

	if (pet->done) {
	    pet->done(pet, 0, pet->cb_data);
	    pet->done = NULL;
	}

	/* Restart the timer */
	timeout.tv_sec = PET_TIMEOUT_SEC;
	timeout.tv_usec = 0;
	os_hnd->start_timer(os_hnd, pet->timer, &timeout, rescan_pet,
			    pet->timer_info);

	if (pet->destroyed) {
	    internal_pet_destroy(pet);
	    return;
	}
    }

    ipmi_unlock(pet->lock);
}

static void lanparm_got_config(ipmi_lanparm_t *pef,
			       int            err,
			       unsigned char  *data,
			       unsigned int   data_len,
			       void           *cb_data);

static int
lanparm_next_config(got_data_t *info)
{
    ipmi_pet_t    *pet = info->pet;
    unsigned int  ch = info->channel;
    parm_check_t  *check;
    int           rv;

    pet->lanparm_check_pos[ch]++;
    if (pet->lanparm_check_pos[ch] >= NUM_LANPARM_SETTINGS) {
	/* Return non-zero, to end the operation. */
	return 1;
    }

    check = &(pet->lanparm_check[pet->lanparm_check_pos[ch]]);

    rv = ipmi_lanparm_get_parm(pet->working_lanparm[ch],
			       check->conf_num, check->set,
			       0, lanparm_got_config, info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(lanparm_got_config): get err: 0x%x", rv);
    }

    return rv;
}

static void
lanparm_set_config(ipmi_lanparm_t *pef,
		   int            err,
		   void           *cb_data)
{
    got_data_t    *info = cb_data;
    ipmi_pet_t    *pet = info->pet;
    int           rv;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pet_op_done(pet);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(lanparm_set_config): set failed: 0x%x", err);
	pet_op_done(pet);
	goto out;
    }

    rv = lanparm_next_config(info);
    if (rv) {
	pet_op_done(pet);
	goto out;
    }
    ipmi_unlock(pet->lock);
 out:
    return;
}

static void
lanparm_got_config(ipmi_lanparm_t *lanparm,
		   int            err,
		   unsigned char  *data,
		   unsigned int   data_len,
		   void           *cb_data)
{
    got_data_t    *info = cb_data;
    ipmi_pet_t    *pet = info->pet;
    unsigned int  ch = info->channel;
    unsigned char val[22];
    int           rv;
    int           pos;
    parm_check_t  *check;
    int           check_failed = 0;
    int           i;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pet_op_done(pet);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(lanparm_got_config): get failed: 0x%x", err);
	pet_op_done(pet);
	goto out;
    }

    pos = pet->lanparm_check_pos[ch];
    check = &(pet->lanparm_check[pos]);

    /* Don't forget to skip the revision number in the length. */
    if (data_len < (check->data_len+1)) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(lanparm_got_config): data length too short for"
		 " config %d, was %d, expected %d", check->conf_num,
		 data_len, check->data_len);
	pet_op_done(pet);
	goto out;
    }

    data++; /* Skip the revision number */

    /* Check the config item we got and make sure it matches.  If it
       does not match, send the proper data for it. */
    for (i=0; i<check->data_len; i++) {
	unsigned char checkdata;

	checkdata = check->data[i];
	if ((data[i] & check->mask[i]) != checkdata) {
	    check_failed = 1;
	    break;
	}
    }

    if (check_failed) {
	for (i=0; i<check->data_len; i++) {
	    unsigned char checkdata;

	    checkdata = check->data[i];
	    val[i] = (data[i] & ~check->mask[i]) | checkdata;
	}
	rv = ipmi_lanparm_set_parm(pet->working_lanparm[ch],
				   check->conf_num, val, check->data_len,
				   lanparm_set_config, info);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "pet.c(lanparm_got_config): sending set: 0x%x",
		     rv);
	    pet_op_done(pet);
	    goto out;
	}
    } else {
	rv = lanparm_next_config(info);
	if (rv) {
	    pet_op_done(pet);
	    goto out;
	}
    }

    ipmi_unlock(pet->lock);
 out:
    return;
}

static void pef_got_config(ipmi_pef_t    *pef,
			   int           err,
			   unsigned char *data,
			   unsigned int  data_len,
			   void          *cb_data);

static int
pef_next_config(got_data_t *info)
{
    ipmi_pet_t    *pet = info->pet;
    unsigned int  ch = info->channel;
    parm_check_t  *check;
    int           rv;

    pet->pef_check_pos[ch]++;
    if (pet->pef_check_pos[ch] >= NUM_PEF_SETTINGS) {
	/* Return non-zero, to end the operation. */
	return 1;
    }

    check = &(pet->pef_check[pet->pef_check_pos[ch]]);

    rv = ipmi_pef_get_parm(pet->working_pef[ch], check->conf_num, check->set,
			   0, pef_got_config, info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_got_control): PEF get err: 0x%x", rv);
    }

    return rv;
}

static void
pef_set_config(ipmi_pef_t    *pef,
	       int           err,
	       void          *cb_data)
{
    got_data_t    *info = cb_data;
    ipmi_pet_t    *pet = info->pet;
    int           rv;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pet_op_done(pet);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_got_control): PEF alloc failed: 0x%x", err);
	pet_op_done(pet);
	goto out;
    }

    rv = pef_next_config(info);
    if (rv) {
	pet_op_done(pet);
	goto out;
    }
    ipmi_unlock(pet->lock);
 out:
    return;
}

static void
pef_got_config(ipmi_pef_t    *pef,
	       int           err,
	       unsigned char *data,
	       unsigned int  data_len,
	       void          *cb_data)
{
    got_data_t    *info = cb_data;
    ipmi_pet_t    *pet = info->pet;
    unsigned int  ch = info->channel;
    unsigned char val[22];
    int           rv;
    int           pos;
    parm_check_t  *check;
    int           check_failed = 0;
    int           i;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pet_op_done(pet);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_got_control): PEF alloc failed: 0x%x", err);
	pet_op_done(pet);
	goto out;
    }

    pos = pet->pef_check_pos[ch];
    check = &(pet->pef_check[pos]);

    /* Don't forget to skip the revision number in the length. */
    if (data_len < check->data_len) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_got_cofnfig): PEF data length too short for"
		 " config %d, was %d, expected %d", check->conf_num,
		 data_len, check->data_len);
	pet_op_done(pet);
	goto out;
    }

    data++; /* Skip the revision number */

    /* Check the config item we got and make sure it matches.  If it
       does not match, send the proper data for it. */
    for (i=0; i<check->data_len; i++) {
	unsigned char checkdata;

	if ((check->conf_num == IPMI_PEFPARM_ALERT_POLICY_TABLE) && (i == 1))
	    /* Channel may vary between connections. */
	    checkdata = pet->channel[ch];
	else
	    checkdata = check->data[i];
	if ((data[i] & check->mask[i]) != checkdata) {
	    check_failed = 1;
	    break;
	}
    }

    if (check_failed) {
	for (i=0; i<check->data_len; i++) {
	    unsigned char checkdata;
	    if ((check->conf_num == IPMI_PEFPARM_ALERT_POLICY_TABLE)
		&& (i == 1))
	    {
		/* Channel may vary between connections. */
		checkdata = pet->channel[ch];
	    } else {
		checkdata = check->data[i];
	    }
	    val[i] = (data[i] & ~check->mask[i]) | checkdata;
	}
	rv = ipmi_pef_set_parm(pef, check->conf_num, val, check->data_len,
			       pef_set_config, info);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "pet.c(pef_got_config): PEF error sending set: 0x%x",
		     rv);
	    pet_op_done(pet);
	    goto out;
	}
    } else {
	rv = pef_next_config(info);
	if (rv) {
	    pet_op_done(pet);
	    goto out;
	}
    }

    ipmi_unlock(pet->lock);
 out:
    return;
}

static void
got_channel(ipmi_mc_t  *mc,
	    ipmi_msg_t *msg,
	    void       *rsp_data)
{
    got_data_t   *info = rsp_data;
    ipmi_pet_t   *pet = info->pet;
    unsigned int ch = info->channel;
    int          rv;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pet_op_done(pet);
	goto out;
    }

    if (msg->data[0] != 0) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(got_channel): Channel fetch error: 0x%x",
		 msg->data[0]);
	pet_op_done(pet);
	goto out;
    }

    if (msg->data_len < 2) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(got_channel): Data length too short");
	pet_op_done(pet);
	goto out;
    }

    pet->channel[ch] = msg->data[1];

    /* Start the configuration process. */
    rv = ipmi_pef_get_parm(pet->working_pef[ch], pet->pef_check[0].conf_num,
			   pet->pef_check[0].set, 0,
			   pef_got_config, info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(got_channel): PEF control get err: 0x%x", rv);
	pet_op_done(pet);
	goto out;
    }

    ipmi_unlock(pet->lock);
 out:
    return;
}

static void
mc_send_chanauth(ipmi_mc_t*mc, void *cb_data)
{
    got_data_t    *info = cb_data;
    unsigned char data[2];
    ipmi_msg_t    msg;
    int           rv;

    /* Find the channel number we are working with, we need it for the
       alert policy table. */
    msg.netfn = IPMI_APP_NETFN;
    msg.cmd = IPMI_GET_CHANNEL_AUTH_CAPABILITIES_CMD;
    msg.data = data;
    msg.data_len = 2;
    data[0] = IPMI_SELF_CHANNEL;
    data[1] = 2; /* Request for the user level, pretty safe operation
		    to get the actual channel. */

    rv = ipmi_mc_send_command(mc, 0, &msg, got_channel, info);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "start_pet_setup: Unable to fetch channel: 0x%x", rv);
	info->err = rv;
    }	    
}

static void
pef_alloced(ipmi_pef_t *pef, int err, void *cb_data)
{
    got_data_t  *info = cb_data;
    ipmi_pet_t  *pet = info->pet;
    ipmi_mcid_t mcid;
    int         rv;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pet_op_done(pet);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_alloced): PEF alloc failed: 0x%x", err);
	pet_op_done(pet);
	goto out;
    }

    mcid = ipmi_pef_get_mc(pef);
    info->err = 0;
    rv = ipmi_mc_pointer_cb(mcid, mc_send_chanauth, info);
    if (!rv)
	rv = info->err;
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "start_pet_setup: Unable to fetch channel: 0x%x", rv);
	pet_op_done(pet);
	goto out;
    }	    

    ipmi_unlock(pet->lock);
 out:
    return;
}

static int
start_pet_setup(ipmi_domain_t *domain,
		ipmi_pet_t    *pet)
{
    int                          rv = 0;
    int                          i;
    ipmi_system_interface_addr_t si;
    ipmi_mc_t                    *mc;
    got_data_t                   *info;

    if (pet->in_progress) {
	rv = EAGAIN;
	goto out;
    }

    for (i=0; i<IPMI_SELF_CHANNEL; i++) {
	si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
	si.channel = i;
	si.lun = 0;

	mc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &si, sizeof(si));
	if (!mc)
	    break;

	info = &(pet->got_data[i]);
	info->channel = i;
	info->pet = pet;

	pet->pef_check_pos[i] = 0;
	rv = ipmi_pef_alloc(mc, pef_alloced, info, &(pet->working_pef[i]));
	if (rv) {
	    ipmi_lanparm_destroy(pet->working_lanparm[i], NULL, NULL);
	    ipmi_log(IPMI_LOG_WARNING,
		     "start_pet_setup: Unable to allocate pef: 0x%x", rv);
	} else {
	    pet->in_progress++;
	}

	pet->lanparm_check_pos[i] = 0;
	rv = ipmi_lanparm_alloc(mc, IPMI_SELF_CHANNEL,
				&(pet->working_lanparm[i]));
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "start_pet_setup: Unable to allocate lanparm: 0x%x",
		     rv);
	} else {
	    rv = ipmi_lanparm_get_parm(pet->working_lanparm[i],
				       IPMI_LANPARM_DEST_TYPE,
				       pet->lan_dest_sel,
				       0,
				       lanparm_got_config,
				       info);
	    if (rv) {
		ipmi_log(IPMI_LOG_WARNING,
			 "start_pet_setup: Unable to get dest type: 0x%x",
			 rv);
		ipmi_lanparm_destroy(pet->working_lanparm[i], NULL, NULL);
		pet->working_lanparm[i] = NULL;
	    } else {
		pet->in_progress++;
	    }
	}
    }
 out:
    return rv;
}

int
ipmi_pet_create(ipmi_domain_t    *domain,
		struct in_addr   ip_addr,
		unsigned char    mac_addr[6],
		unsigned int     eft_sel,
		unsigned int     apt_sel,
		unsigned int     lan_dest_sel,
		ipmi_pet_done_cb done,
		void             *cb_data,
		ipmi_pet_t       **ret_pet)
{
    ipmi_pet_t     *pet;
    int            rv;
    os_handler_t   *os_hnd;

    pet = ipmi_mem_alloc(sizeof(*pet));
    if (!pet)
	return ENOMEM;
    memset(pet, 0, sizeof(*pet));

    pet->domain = ipmi_domain_convert_to_id(domain);
    pet->ip_addr = ip_addr;
    pet->eft_sel = eft_sel;
    pet->apt_sel = apt_sel;
    pet->lan_dest_sel = lan_dest_sel;
    pet->done = done;
    pet->cb_data = cb_data;
    pet->in_progress = 0;

    /* Set up all the data we want in the PEF and LANPARMs
       configuration. */
    pet->pef_check[0].conf_num = IPMI_PEFPARM_CONTROL;
    pet->pef_check[0].data_len = 1;
    pet->pef_check[0].data[0] = 1;
    pet->pef_check[0].mask[0] = 1;
    pet->pef_check[1].conf_num = IPMI_PEFPARM_ACTION_GLOBAL_CONTROL;
    pet->pef_check[1].data_len = 1;
    pet->pef_check[1].data[0] = 1;
    pet->pef_check[1].mask[0] = 1;
    pet->pef_check[2].conf_num = IPMI_PEFPARM_EVENT_FILTER_TABLE;
    pet->pef_check[2].set = eft_sel;
    pet->pef_check[2].data_len = 22;
    memset(pet->pef_check[2].data, 0xff, 9);
    memset(pet->pef_check[2].data+9, 0, 22-9);
    memset(pet->pef_check[2].mask, 0xff, 22);
    pet->pef_check[2].data[0] = eft_sel;
    pet->pef_check[2].mask[0] = 0x7f;
    pet->pef_check[2].data[1] = 0x80;
    pet->pef_check[2].mask[1] = 0x80;
    pet->pef_check[2].data[2] = 0x01;
    pet->pef_check[2].data[2] = apt_sel;
    pet->pef_check[2].mask[3] = 0x0f;
    pet->pef_check[2].data[4] = 0;
    pet->pef_check[3].conf_num = IPMI_PEFPARM_ALERT_POLICY_TABLE;
    pet->pef_check[3].set = apt_sel;
    pet->pef_check[3].data_len = 3;
    pet->pef_check[3].data[0] = apt_sel;
    pet->pef_check[3].mask[0] = 0x7f;
    pet->pef_check[3].data[1] = 0x08;
    pet->pef_check[3].mask[1] = 0x0f;
    pet->pef_check[3].data[2] = 0x00; /* Channel set when found */
    pet->pef_check[3].mask[2] = 0x0f;
    pet->pef_check[3].data[3] = 0x00;
    pet->pef_check[3].mask[3] = 0xff;

    pet->lanparm_check[0].conf_num = IPMI_LANPARM_DEST_TYPE;
    pet->lanparm_check[0].set = lan_dest_sel;
    pet->lanparm_check[0].data_len = 4;
    pet->lanparm_check[0].data[0] = lan_dest_sel;
    pet->lanparm_check[0].mask[0] = 0x0f;
    pet->lanparm_check[0].data[1] = 0x80;
    pet->lanparm_check[0].mask[1] = 0x87;
    pet->lanparm_check[0].data[2] = 1;
    pet->lanparm_check[0].mask[2] = 0xff;
    pet->lanparm_check[0].data[3] = 0x80;
    pet->lanparm_check[0].mask[3] = 0x87;
    pet->lanparm_check[1].conf_num = IPMI_LANPARM_DEST_ADDR;
    pet->lanparm_check[1].set = lan_dest_sel;
    pet->lanparm_check[1].data_len = 13;
    pet->lanparm_check[1].data[0] = lan_dest_sel;
    pet->lanparm_check[1].mask[0] = 0x0f;
    pet->lanparm_check[1].data[1] = 0x00;
    pet->lanparm_check[1].mask[1] = 0xf0;
    pet->lanparm_check[1].data[2] = 0x00;
    pet->lanparm_check[1].mask[2] = 0x01;
    memcpy(pet->lanparm_check[1].data+3, &ip_addr, 4);
    memcpy(pet->lanparm_check[1].data+7, mac_addr, 6);

    os_hnd = ipmi_domain_get_os_hnd(domain);
    pet->os_hnd = os_hnd;
    rv = ipmi_create_lock_os_hnd(os_hnd, &pet->lock);
    if (rv) {
	ipmi_mem_free(pet);
	return rv;
    }

    ipmi_rwlock_write_lock(pet_lock);
    rv = open_pet_socket();
    if (rv)
	goto out_unlock_err;

    /* Start a timer for this PET to periodically check it. */
    pet->timer_info = ipmi_mem_alloc(sizeof(*(pet->timer_info)));
    if (!pet->timer_info) {
	rv = ENOMEM;
	goto out_unlock_err;
    }
    pet->timer_info->cancelled = 0;
    pet->timer_info->os_hnd = os_hnd;
    pet->timer_info->pet = pet;
    rv = os_hnd->alloc_timer(os_hnd, &pet->timer);
    if (rv)
	goto out_unlock_err;

    rv = start_pet_setup(domain, pet);
    if (rv)
	goto out_unlock_err;

    pet->next = &pet_list;
    pet->prev = pet_list.prev;
    pet_list.prev->next = pet;
    pet_list.prev = pet;

    ipmi_rwlock_write_unlock(pet_lock);
    return 0;

 out_unlock_err:
    shutdown_pet_fd();
    if (pet->timer_info) {
	if (pet->timer) {
	    if (os_hnd->stop_timer(os_hnd, pet->timer) == 0)
		ipmi_mem_free(pet->timer_info);
	    else
		pet->timer_info->cancelled = 1;
	} else
	    ipmi_mem_free(pet->timer_info);
    }
    ipmi_rwlock_write_unlock(pet_lock);
    ipmi_mem_free(pet);
    return rv;
}

static void
rescan_pet_domain(ipmi_domain_t *domain, void *cb_data)
{
    pet_timer_t *timer_info = cb_data;
    ipmi_pet_t  *pet = timer_info->pet;

    timer_info->err = start_pet_setup(domain, pet);
}

static void
rescan_pet(void *cb_data, os_hnd_timer_id_t *id)
{
    pet_timer_t    *timer_info = cb_data;
    ipmi_pet_t     *pet;
    int            rv;
    struct timeval timeout;

    ipmi_rwlock_read_lock(pet_lock);

    if (timer_info->cancelled) {
	ipmi_mem_free(timer_info);
	ipmi_rwlock_read_unlock(pet_lock);
	return;
    }

    pet = timer_info->pet;
    ipmi_lock(pet->lock);
    timer_info->err = 0;
    rv = ipmi_domain_pointer_cb(pet->domain, rescan_pet_domain, timer_info);
    if (!rv)
	rv = timer_info->err;

    if (rv) {
	os_handler_t *os_hnd = timer_info->os_hnd;
	/* Got an error, just restart the timer */
	timeout.tv_sec = PET_TIMEOUT_SEC;
	timeout.tv_usec = 0;
	os_hnd->start_timer(os_hnd, pet->timer, &timeout, rescan_pet,
			    pet->timer_info);
    }

    ipmi_unlock(pet->lock);
    ipmi_rwlock_read_unlock(pet_lock);
}

int
ipmi_pet_destroy(ipmi_pet_t       *pet,
		 ipmi_pet_done_cb done,
		 void             *cb_data)

{
    ipmi_pet_t *e;
    int        rv = 0;

    ipmi_rwlock_write_lock(pet_lock);

    if (pet->timer_info) {
	os_handler_t *os_hnd = pet->timer_info->os_hnd;
	if (pet->timer) {
	    if (os_hnd->stop_timer(os_hnd, pet->timer) == 0)
		ipmi_mem_free(pet->timer_info);
	    else
		pet->timer_info->cancelled = 1;
	} else
	    ipmi_mem_free(pet->timer_info);
    }

    e = pet_list.next;
    while (e != &pet_list) {
	if (e == pet)
	    break;
	e = e->next;
    }
    if (e == &pet_list) {
	rv = EINVAL;
	goto out_unlock_err;
    }

    pet->next = pet->next->prev;
    pet->prev = pet->prev->next;

    ipmi_lock(pet->lock);
    pet->destroyed = 1;
    pet->destroy_done = done;
    pet->destroy_cb_data = cb_data;

    if (! pet->in_progress)
	internal_pet_destroy(pet);
    else
	ipmi_unlock(pet->lock);

    shutdown_pet_fd();

 out_unlock_err:
    ipmi_rwlock_write_unlock(pet_lock);
    return rv;
}

int
_ipmi_pet_init(void)
{
    int rv;

    rv = ipmi_create_global_rwlock(&pet_lock);
    if (rv)
	return rv;
    
    return 0;
}

void
_ipmi_pet_shutdown(void)
{
    ipmi_pet_t *e, *n;

    e = pet_list.next;
    while (e != &pet_list) {
	n = e->next;
	ipmi_pet_destroy(e, NULL, NULL);
	e = n;
    }
    ipmi_destroy_rwlock(pet_lock);
}
