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
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_pet.h>
#include <OpenIPMI/ipmi_pef.h>
#include <OpenIPMI/ipmi_lanparm.h>
#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_domain.h>

/* Recheck the PET config every 10 minutes. */
#define PET_TIMEOUT_SEC 600

/* Time between alert retries (in seconds). */
#define IPMI_LANPARM_DEFAULT_ALERT_RETRY_TIMEOUT 1

/* Alerts get retried this many times. */
#define IPMI_LANPARM_DEFAULT_ALERT_RETRIES 3

static ipmi_rwlock_t  *pet_lock = NULL;

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

    unsigned int connection;
    unsigned int channel;
    ipmi_pet_t   *pet;
    int          pef_err;
    int          pef_lock_broken;
    int          lanparm_err;
    int          lanparm_lock_broken;
    int          changed;

    int            lanparm_check_pos;
    ipmi_lanparm_t *lanparm;

    int          pef_check_pos;
    ipmi_pef_t   *pef;

    /* The domain's OS handler */
    os_handler_t     *os_hnd;

    ipmi_pet_done_cb done;
    void             *cb_data;

    ipmi_pet_done_cb destroy_done;
    void             *destroy_cb_data;

    ipmi_lock_t      *lock;

    int              in_progress;

    /* The LAN configuration parameters to check. */
    parm_check_t     lanparm_check[NUM_LANPARM_SETTINGS];

    /* The PEF configuration parameters to check */
    parm_check_t     pef_check[NUM_PEF_SETTINGS];

    /* Timer to check the configuration periodically. */
    pet_timer_t       *timer_info;
    os_hnd_timer_id_t *timer;

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
    os_handler_t   *os_hnd = pet->os_hnd;

    pet->in_progress--;

    if (pet->in_progress == 0) {
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

static void
lanparm_unlocked(ipmi_lanparm_t *lanparm,
		 int            err,
		 void           *cb_data)
{
    ipmi_pet_t *pet = cb_data;

    ipmi_lock(pet->lock);
    ipmi_lanparm_destroy(pet->lanparm, NULL, NULL);
    pet->lanparm = NULL;
    pet_op_done(pet);
}

static void
lanparm_commited(ipmi_lanparm_t *lanparm,
		 int            err,
		 void           *cb_data)
{
    ipmi_pet_t    *pet = cb_data;
    int           rv;
    unsigned char data[1];

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	ipmi_lanparm_destroy(pet->lanparm, NULL, NULL);
	pet->lanparm = NULL;
	pet_op_done(pet);
	goto out;
    }

    /* Ignore the error, committing is optional. */

    data[0] = 0; /* clear lock */
    rv = ipmi_lanparm_set_parm(pet->lanparm, 0, data, 1,
			   lanparm_unlocked, pet);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(lanparm_commited): error clearing lock: 0x%x", rv);
	ipmi_lanparm_destroy(pet->lanparm, NULL, NULL);
	pet->lanparm = NULL;
	pet_op_done(pet);
	goto out;
    }
    ipmi_unlock(pet->lock);
 out:
    return;
}

/* Must be called locked, this will unlock the PET. */
static void
lanparm_op_done(ipmi_pet_t *pet, int err)
{
    int           rv;

    pet->lanparm_err = err;
    if (pet->lanparm_lock_broken) {
	/* Locking is not supported. */
	ipmi_lanparm_destroy(pet->lanparm, NULL, NULL);
	pet->lanparm = NULL;
	pet_op_done(pet);
	goto out;
    } else {
	unsigned char data[1];

	if (!pet->lanparm_err && pet->changed) {
	    /* Don't commit if an error occurred. */
	    data[0] = 2; /* commit */
	    rv = ipmi_lanparm_set_parm(pet->lanparm, 0, data, 1,
				       lanparm_commited, pet);
	} else {
	    data[0] = 0; /* clear lock */
	    rv = ipmi_lanparm_set_parm(pet->lanparm, 0, data, 1,
				       lanparm_unlocked, pet);
	}
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "pet.c(lanparm_op_done): error clearing lock: 0x%x", rv);
	    ipmi_lanparm_destroy(pet->lanparm, NULL, NULL);
	    pet->lanparm = NULL;
	    pet_op_done(pet);
	    goto out;
	}
    }
    ipmi_unlock(pet->lock);
 out:
    return;
}

static void lanparm_got_config(ipmi_lanparm_t *lanparm,
			       int            err,
			       unsigned char  *data,
			       unsigned int   data_len,
			       void           *cb_data);

static int
lanparm_next_config(ipmi_pet_t *pet)
{
    parm_check_t  *check;
    int           rv;

    pet->lanparm_check_pos++;
    if (pet->lanparm_check_pos >= NUM_LANPARM_SETTINGS) {
	/* Return non-zero, to end the operation. */
	return 1;
    }

    check = &(pet->lanparm_check[pet->lanparm_check_pos]);

    rv = ipmi_lanparm_get_parm(pet->lanparm,
			       check->conf_num, check->set,
			       0, lanparm_got_config, pet);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(lanparm_next_config): get err for %d: 0x%x",
		 pet->lanparm_check_pos, rv);
    }

    return rv;
}

static void
lanparm_set_config(ipmi_lanparm_t *lanparm,
		   int            err,
		   void           *cb_data)
{
    ipmi_pet_t    *pet = cb_data;
    int           rv;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	lanparm_op_done(pet, ECANCELED);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(lanparm_set_config): set failed for %d: 0x%x",
		 pet->lanparm_check_pos, err);
	lanparm_op_done(pet, err);
	goto out;
    }

    rv = lanparm_next_config(pet);
    if (rv) {
	lanparm_op_done(pet, rv);
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
    ipmi_pet_t    *pet = cb_data;
    unsigned char val[22];
    int           rv;
    int           pos;
    parm_check_t  *check;
    int           check_failed = 0;
    int           i;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	lanparm_op_done(pet, ECANCELED);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(lanparm_got_config): get failed for %d: 0x%x",
		 pet->lanparm_check_pos, err);
	lanparm_op_done(pet, err);
	goto out;
    }

    pos = pet->lanparm_check_pos;
    check = &(pet->lanparm_check[pos]);

    /* Don't forget to skip the revision number in the length. */
    if (data_len < (check->data_len+1)) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(lanparm_got_config): data length too short for"
		 " config %d, was %d, expected %d", check->conf_num,
		 data_len, check->data_len);
	lanparm_op_done(pet, EINVAL);
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
	rv = ipmi_lanparm_set_parm(pet->lanparm,
				   check->conf_num, val, check->data_len,
				   lanparm_set_config, pet);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "pet.c(lanparm_got_config): sending set: 0x%x",
		     rv);
	    lanparm_op_done(pet, rv);
	    goto out;
	}
    } else {
	rv = lanparm_next_config(pet);
	if (rv) {
	    lanparm_op_done(pet, rv);
	    goto out;
	}
    }

    ipmi_unlock(pet->lock);
 out:
    return;
}

static void
pef_unlocked(ipmi_pef_t    *pef,
	     int           err,
	     void          *cb_data)
{
    ipmi_pet_t *pet = cb_data;

    ipmi_lock(pet->lock);
    ipmi_pef_destroy(pet->pef, NULL, NULL);
    pet->pef = NULL;
    pet_op_done(pet);
}

static void
pef_commited(ipmi_pef_t    *pef,
	     int           err,
	     void          *cb_data)
{
    ipmi_pet_t    *pet = cb_data;
    int           rv;
    unsigned char data[1];

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	ipmi_pef_destroy(pet->pef, NULL, NULL);
	pet->pef = NULL;
	pet_op_done(pet);
	goto out;
    }

    /* Ignore the error, committing is optional. */

    data[0] = 0; /* clear lock */
    rv = ipmi_pef_set_parm(pet->pef, 0, data, 1,
			   pef_unlocked, pet);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_commited): error clearing lock: 0x%x", rv);
	ipmi_pef_destroy(pet->pef, NULL, NULL);
	pet->pef = NULL;
	pet_op_done(pet);
	goto out;
    }
    ipmi_unlock(pet->lock);
 out:
    return;
}

/* Must be called locked, this will unlock the PET. */
static void
pef_op_done(ipmi_pet_t *pet, int err)
{
    int           rv;

    pet->pef_err = err;
    if (pet->pef_lock_broken) {
	/* Locking is not supported. */
	ipmi_pef_destroy(pet->pef, NULL, NULL);
	pet->pef = NULL;
	pet_op_done(pet);
	goto out;
    } else {
	unsigned char data[1];

	if (!pet->pef_err && pet->changed) {
	    /* Don't commit if an error occurred. */
	    data[0] = 2; /* commit */
	    rv = ipmi_pef_set_parm(pet->pef, 0, data, 1, pef_commited, pet);
	} else {
	    data[0] = 0; /* clear lock */
	    rv = ipmi_pef_set_parm(pet->pef, 0, data, 1, pef_unlocked, pet);
	}
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "pet.c(pef_op_done): error clearing lock: 0x%x", rv);
	    pet_op_done(pet);
	    ipmi_pef_destroy(pet->pef, NULL, NULL);
	    pet->pef = NULL;
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
pef_next_config(ipmi_pet_t *pet)
{
    parm_check_t  *check;
    int           rv;

    pet->pef_check_pos++;
    if (pet->pef_check_pos >= NUM_PEF_SETTINGS) {
	/* Return non-zero, to end the operation. */
	return 1;
    }

    check = &(pet->pef_check[pet->pef_check_pos]);

    rv = ipmi_pef_get_parm(pet->pef, check->conf_num, check->set,
			   0, pef_got_config, pet);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_next_config): PEF get err: 0x%x", rv);
    }

    return rv;
}

static void
pef_set_config(ipmi_pef_t    *pef,
	       int           err,
	       void          *cb_data)
{
    ipmi_pet_t    *pet = cb_data;
    int           rv;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pef_op_done(pet, ECANCELED);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_set_config): PEF set failed for %d: 0x%x",
		 pet->pef_check_pos, err);
	pef_op_done(pet, err);
	goto out;
    }

    rv = pef_next_config(pet);
    if (rv) {
	pef_op_done(pet, rv);
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
    ipmi_pet_t    *pet = cb_data;
    unsigned char val[22];
    int           rv;
    int           pos;
    parm_check_t  *check;
    int           check_failed = 0;
    int           i;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pef_op_done(pet, ECANCELED);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_got_control): PEF alloc failed: 0x%x", err);
	pef_op_done(pet, err);
	goto out;
    }

    pos = pet->pef_check_pos;
    check = &(pet->pef_check[pos]);

    /* Don't forget to skip the revision number in the length. */
    if (data_len < check->data_len) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_got_cofnfig): PEF data length too short for"
		 " config %d, was %d, expected %d", check->conf_num,
		 data_len, check->data_len);
	pef_op_done(pet, EINVAL);
	goto out;
    }

    data++; /* Skip the revision number */

    /* Check the config item we got and make sure it matches.  If it
       does not match, send the proper data for it. */
    for (i=0; i<check->data_len; i++) {
	if ((data[i] & check->mask[i]) != check->data[i]) {
	    check_failed = 1;
	    break;
	}
    }

    if (check_failed) {
	for (i=0; i<check->data_len; i++)
	    val[i] = (data[i] & ~check->mask[i]) | check->data[i];
	rv = ipmi_pef_set_parm(pef, check->conf_num, val, check->data_len,
			       pef_set_config, pet);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "pet.c(pef_got_config): PEF error sending set: 0x%x",
		     rv);
	    pef_op_done(pet, rv);
	    goto out;
	}
    } else {
	rv = pef_next_config(pet);
	if (rv) {
	    pef_op_done(pet, rv);
	    goto out;
	}
    }

    ipmi_unlock(pet->lock);
 out:
    return;
}

static void
pef_locked(ipmi_pef_t *pef,
	   int        err,
	   void       *cb_data)
{
    ipmi_pet_t    *pet = cb_data;
    int           rv;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pef_op_done(pet, ECANCELED);
	goto out;
    }

    if (err == 0x80) {
	/* No support for locking, just set it so and continue. */
	pet->pef_lock_broken = 1;
    } else if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_locked): PEF lock failed: 0x%x", err);
	pef_op_done(pet, err);
	goto out;
    }

    /* Start the configuration process. */
    rv = ipmi_pef_get_parm(pet->pef, pet->pef_check[0].conf_num,
			   pet->pef_check[0].set, 0,
			   pef_got_config, pet);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_locked): PEF control get err: 0x%x", rv);
	pef_op_done(pet, rv);
	goto out;
    }

    ipmi_unlock(pet->lock);
 out:
    return;
}

static void
pef_alloced(ipmi_pef_t *pef, int err, void *cb_data)
{
    ipmi_pet_t    *pet = cb_data;
    unsigned char data[1];
    int           rv;

    ipmi_lock(pet->lock);
    if (pet->destroyed) {
	pef_op_done(pet, ECANCELED);
	goto out;
    }

    if (err) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_alloced): PEF alloc failed: 0x%x", err);
	pef_op_done(pet, err);
	goto out;
    }

    /* Start the configuration process. */
    data[0] = 1; /* Attempt to lock */
    rv = ipmi_pef_set_parm(pet->pef, 0, data, 1,
			   pef_locked, pet);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "pet.c(pef_alloced): PEF control get err: 0x%x", rv);
	pef_op_done(pet, rv);
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
    ipmi_system_interface_addr_t si;
    ipmi_mc_t                    *mc;

    if (pet->in_progress) {
	rv = EAGAIN;
	goto out;
    }

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = pet->connection;
    si.lun = 0;

    mc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &si, sizeof(si));
    if (!mc)
	return EINVAL;

    pet->pet = pet;
    pet->pef_lock_broken = 0;
    pet->pef_err = 0;
    pet->lanparm_lock_broken = 0;
    pet->lanparm_err = 0;

    pet->pef_check_pos = 0;
    rv = ipmi_pef_alloc(mc, pef_alloced, pet, &pet->pef);
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "start_pet_setup: Unable to allocate pef: 0x%x", rv);
	goto out;
    } else {
	pet->in_progress++;
    }

    /* Now that we have the channel, set up the lan parms. */
    pet->lanparm_check_pos = 0;
    rv = ipmi_lanparm_alloc(mc, pet->channel, &(pet->lanparm));
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "start_pet_setup: Unable to allocate lanparm: 0x%x",
		 rv);
    } else {
	rv = ipmi_lanparm_get_parm(pet->lanparm,
				   IPMI_LANPARM_DEST_TYPE,
				   pet->lan_dest_sel,
				   0,
				   lanparm_got_config,
				   pet);
	if (rv) {
	    ipmi_log(IPMI_LOG_WARNING,
		     "start_pet_setup: Unable to get dest type: 0x%x",
		     rv);
	    ipmi_lanparm_destroy(pet->lanparm, NULL, NULL);
	    pet->lanparm = NULL;
	} else {
	    pet->in_progress++;
	}
    }
    rv = 0; /* We continue with the PEF run, even if the lanparm fails. */

 out:
    _ipmi_mc_put(mc);
    return rv;
}

int
ipmi_pet_create(ipmi_domain_t    *domain,
		unsigned int     connection,
		unsigned int     channel,
		struct in_addr   ip_addr,
		unsigned char    mac_addr[6],
		unsigned int     eft_sel,
		unsigned int     policy_num,
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
    pet->connection = connection;
    pet->channel = channel;
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
    pet->pef_check[2].data_len = 21;
    memset(pet->pef_check[2].data, 0xff, 10);
    memset(pet->pef_check[2].data+10, 0, 21-9);
    memset(pet->pef_check[2].mask, 0xff, 21);
    pet->pef_check[2].data[0] = eft_sel;
    pet->pef_check[2].mask[0] = 0x7f;
    pet->pef_check[2].data[1] = 0x80;
    pet->pef_check[2].mask[1] = 0x80;
    pet->pef_check[2].data[2] = 0x01;
    pet->pef_check[2].mask[2] = 0x3f;
    pet->pef_check[2].data[3] = policy_num;
    pet->pef_check[2].mask[3] = 0x0f;
    pet->pef_check[2].data[4] = 0;
    pet->pef_check[2].data[10] = 0xff;
    pet->pef_check[2].data[11] = 0xff;
    pet->pef_check[3].conf_num = IPMI_PEFPARM_ALERT_POLICY_TABLE;
    pet->pef_check[3].set = apt_sel;
    pet->pef_check[3].data_len = 4;
    pet->pef_check[3].data[0] = apt_sel;
    pet->pef_check[3].mask[0] = 0x7f;
    pet->pef_check[3].data[1] = 0x08 | (policy_num << 4);
    pet->pef_check[3].mask[1] = 0xff;
    pet->pef_check[3].data[2] = (channel << 4) | lan_dest_sel;
    pet->pef_check[3].mask[2] = 0xff;
    pet->pef_check[3].data[3] = 0;
    pet->pef_check[3].mask[3] = 0xff;

    pet->lanparm_check[0].conf_num = IPMI_LANPARM_DEST_TYPE;
    pet->lanparm_check[0].set = lan_dest_sel;
    pet->lanparm_check[0].data_len = 4;
    pet->lanparm_check[0].data[0] = lan_dest_sel;
    pet->lanparm_check[0].mask[0] = 0x0f;
    pet->lanparm_check[0].data[1] = 0x80;
    pet->lanparm_check[0].mask[1] = 0x87;
    pet->lanparm_check[0].data[2] = IPMI_LANPARM_DEFAULT_ALERT_RETRY_TIMEOUT;
    pet->lanparm_check[0].mask[2] = 0xff;
    pet->lanparm_check[0].data[3] = IPMI_LANPARM_DEFAULT_ALERT_RETRIES;
    pet->lanparm_check[0].mask[3] = 0x07;
    pet->lanparm_check[1].conf_num = IPMI_LANPARM_DEST_ADDR;
    pet->lanparm_check[1].set = lan_dest_sel;
    pet->lanparm_check[1].data_len = 13;
    pet->lanparm_check[1].data[0] = lan_dest_sel;
    pet->lanparm_check[1].mask[0] = 0x0f;
    pet->lanparm_check[1].data[1] = 0x00;
    pet->lanparm_check[1].mask[1] = 0xf0;
    pet->lanparm_check[1].data[2] = 0x00;
    pet->lanparm_check[1].mask[2] = 0x01;
    memset(pet->lanparm_check[1].mask+3, 0xff, 10);
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
    if (pet->timer_info) {
	if (pet->timer) {
	    if (os_hnd->stop_timer(os_hnd, pet->timer) == 0) {
		os_hnd->free_timer(os_hnd, pet->timer);
		ipmi_mem_free(pet->timer_info);
	    } else {
		pet->timer_info->cancelled = 1;
	    }
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
	timer_info->os_hnd->free_timer(timer_info->os_hnd, id);
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
	    if (os_hnd->stop_timer(os_hnd, pet->timer) == 0) {
		os_hnd->free_timer(os_hnd, pet->timer);
		ipmi_mem_free(pet->timer_info);
	    } else {
		pet->timer_info->cancelled = 1;
	    }
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

    pet->next->prev = pet->prev;
    pet->prev->next = pet->next;

    ipmi_lock(pet->lock);
    pet->destroyed = 1;
    pet->destroy_done = done;
    pet->destroy_cb_data = cb_data;

    if (! pet->in_progress)
	internal_pet_destroy(pet);
    else
	ipmi_unlock(pet->lock);

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
