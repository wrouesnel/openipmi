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
#include <stdio.h>

#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_pet.h>
#include <OpenIPMI/ipmi_pef.h>
#include <OpenIPMI/ipmi_lanparm.h>
#include <OpenIPMI/ipmi_msgbits.h>

#include <OpenIPMI/internal/ipmi_int.h>
#include <OpenIPMI/internal/locked_list.h>
#include <OpenIPMI/internal/ipmi_domain.h>
#include <OpenIPMI/internal/ipmi_mc.h>

/* Recheck the PET config every 10 minutes. */
#define PET_TIMEOUT_SEC 600

/* Time between alert retries (in seconds). */
#define IPMI_LANPARM_DEFAULT_ALERT_RETRY_TIMEOUT 1

/* Alerts get retried this many times. */
#define IPMI_LANPARM_DEFAULT_ALERT_RETRIES 3

#define IPMI_PET_ATTR_NAME "ipmi_pet"


/* This data structure defines a data/mask setting for a parameter,
   either from the LAN or PEF parms. */
typedef struct parm_check_s
{
    unsigned char conf_num; /* The number we are interested in. */
    unsigned char set;      /* The specific selector. */
    unsigned int  data_len; /* The length of the data we are using. */
    unsigned char data[22]; /* The actual data. */
    unsigned char mask[22]; /* The mask bits used to mask what we compare. */
} parm_check_t;

/* Information for running the timer.  Note that there is no lock in
   the timer, since the timer is only deleted when the pet_lock is
   held write, we read-lock the pet timer to avoid locking problem. */
typedef struct pet_timer_s {
    int          cancelled;
    int          running;
    os_handler_t *os_hnd;
    ipmi_lock_t  *lock; /* Lock is here because we need it in the timer. */
    ipmi_pet_t   *pet;
    int          err;
} pet_timer_t;

#define NUM_PEF_SETTINGS 4
#define NUM_LANPARM_SETTINGS 2

struct ipmi_pet_s
{
    int destroyed;
    int in_list;

    unsigned int refcount;

    char name[IPMI_PET_NAME_LEN];

    /* Configuration parameters */
    ipmi_mcid_t      mc;
    ipmi_domain_id_t domain;
    struct in_addr   ip_addr;
    char             mac_addr[6];
    unsigned int     policy_num;
    unsigned int     eft_sel;
    unsigned int     apt_sel;
    unsigned int     lan_dest_sel;

    unsigned int channel;
    ipmi_pet_t   *pet;
    int          pef_err;
    int          pef_lock_broken;
    int          lanparm_err;
    int          lanparm_lock_broken;
    int          changed_lanparm;
    int          changed_pef;

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

    int              in_progress;

    /* The LAN configuration parameters to check. */
    parm_check_t     lanparm_check[NUM_LANPARM_SETTINGS];

    /* The PEF configuration parameters to check */
    parm_check_t     pef_check[NUM_PEF_SETTINGS];

    /* Timer to check the configuration periodically. */
    pet_timer_t       *timer_info;
    os_hnd_timer_id_t *timer;
};

static void rescan_pet(void *cb_data, os_hnd_timer_id_t *id);

static void
pet_lock(ipmi_pet_t *pet)
{
    ipmi_lock(pet->timer_info->lock);
}

static void
pet_unlock(ipmi_pet_t *pet)
{
    ipmi_unlock(pet->timer_info->lock);
}

static void
internal_pet_destroy(ipmi_pet_t *pet)
{
    os_handler_t *os_hnd = pet->timer_info->os_hnd;

    if (pet->in_list) {
	ipmi_domain_attr_t *attr;
	locked_list_t      *pets;
	int                rv;
	rv = ipmi_domain_id_find_attribute(pet->domain,
					   IPMI_PET_ATTR_NAME, &attr);
	if (!rv) {
	    pet->refcount++;
	    pet->in_list = 0;
	    pet_unlock(pet);
	
	    pets = ipmi_domain_attr_get_data(attr);

	    locked_list_remove(pets, pet, NULL);
	    ipmi_domain_attr_put(attr);
	    pet_lock(pet);
	    /* While we were unlocked, someone may have come in and
	       grabbed the PET by iterating the list of PETs.  That's
	       ok, we just let them handle the destruction since this
	       code will not be entered again. */
	    if (pet->refcount != 1) {
		pet->refcount--;
		pet_unlock(pet);
		return;
	    }
	}
    }
    pet_unlock(pet);

    if (os_hnd->stop_timer(os_hnd, pet->timer) == 0) {
	ipmi_destroy_lock(pet->timer_info->lock);
	os_hnd->free_timer(os_hnd, pet->timer);
	ipmi_mem_free(pet->timer_info);
    } else {
	pet->timer_info->cancelled = 1;
    }

    if (pet->destroy_done) {
	pet->destroy_done(pet, 0, pet->destroy_cb_data);
    }

    ipmi_mem_free(pet);
}

static void
pet_get_nolock(ipmi_pet_t *pet)
{
    pet->refcount++;
}

static void
pet_get(ipmi_pet_t *pet)
{
    pet_lock(pet);
    pet_get_nolock(pet);
    pet_unlock(pet);
}

/* Be very careful, only call this when the refcount cannot go to zero. */
static void
pet_put_nolock(ipmi_pet_t *pet)
{
    pet->refcount--;
}

static void
pet_put_locked(ipmi_pet_t *pet)
{
    pet->refcount--;
    if (pet->refcount == 0) {
	internal_pet_destroy(pet);
	return;
    }
    pet_unlock(pet);
}

static void
pet_put(ipmi_pet_t *pet)
{
    pet_lock(pet);
    pet_put_locked(pet);
}

void
ipmi_pet_ref(ipmi_pet_t *pet)
{
    pet_get(pet);
}

void
ipmi_pet_deref(ipmi_pet_t *pet)
{
    pet_put(pet);
}

static int
pet_attr_init(ipmi_domain_t *domain, void *cb_data, void **data)
{
    locked_list_t *pets;
    
    pets = locked_list_alloc(ipmi_domain_get_os_hnd(domain));
    if (!pets)
	return ENOMEM;

    *data = pets;
    return 0;
}

static int
destroy_pet(void *cb_data, void *item1, void *item2)
{
    ipmi_pet_t *pet = item1;

    pet_lock(pet);
    pet->in_list = 0;
    pet_unlock(pet);
    return LOCKED_LIST_ITER_CONTINUE;
}

static void
pet_attr_destroy(void *cb_data, void *data)
{
    locked_list_t *pets = data;

    locked_list_iterate(pets, destroy_pet, NULL);
    locked_list_destroy(pets);
}

/* Must be called locked, this will unlock the PET. */
static void
pet_op_done(ipmi_pet_t *pet)
{
    struct timeval timeout;
    os_handler_t   *os_hnd = pet->os_hnd;

    pet->in_progress--;

    if (pet->in_progress == 0) {
	if (pet->lanparm) {
	    ipmi_lanparm_destroy(pet->lanparm, NULL, NULL);
	    pet->lanparm = NULL;
	}

	if (pet->done) {
	    ipmi_pet_done_cb done = pet->done;
	    void             *cb_data = pet->cb_data;
	    pet->done = NULL;
	    pet_unlock(pet);
	    done(pet, 0, cb_data);
	    pet_lock(pet);
	}

	/* Restart the timer */
	timeout.tv_sec = PET_TIMEOUT_SEC;
	timeout.tv_usec = 0;
	os_hnd->start_timer(os_hnd, pet->timer, &timeout, rescan_pet,
			    pet->timer_info);
	pet->timer_info->running = 1;

    }

    pet_put_locked(pet);
}

static void
lanparm_unlocked(ipmi_lanparm_t *lanparm,
		 int            err,
		 void           *cb_data)
{
    ipmi_pet_t *pet = cb_data;

    pet_lock(pet);
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

    pet_lock(pet);
    if (pet->destroyed) {
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
    pet_unlock(pet);
 out:
    return;
}

/* Must be called locked, this will unlock the PET. */
static void
lanparm_op_done(ipmi_pet_t *pet, int err)
{
    int           rv;

    /* Cheap hack, -1 means stop. */
    if (err == -1)
	err = 0;

    pet->lanparm_err = err;
    if (pet->lanparm_lock_broken) {
	/* Locking is not supported. */
	pet_op_done(pet);
	goto out;
    } else {
	unsigned char data[1];

	if (!pet->lanparm_err && pet->changed_lanparm) {
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
    pet_unlock(pet);
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
	return -1;
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

    pet_lock(pet);
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
    pet_unlock(pet);
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
    unsigned int  i;

    pet_lock(pet);
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
	pet->changed_lanparm = 1;
    } else {
	rv = lanparm_next_config(pet);
	if (rv) {
	    lanparm_op_done(pet, rv);
	    goto out;
	}
    }

    pet_unlock(pet);
 out:
    return;
}

static void
pef_unlocked(ipmi_pef_t    *pef,
	     int           err,
	     void          *cb_data)
{
    ipmi_pet_t *pet = cb_data;

    pet_lock(pet);
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

    pet_lock(pet);
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
    pet_unlock(pet);
 out:
    return;
}

/* Must be called locked, this will unlock the PET. */
static void
pef_op_done(ipmi_pet_t *pet, int err)
{
    int           rv;

    /* Cheap hack, -1 means stop. */
    if (err == -1)
	err = 0;

    pet->pef_err = err;
    if (pet->pef_lock_broken) {
	/* Locking is not supported. */
	ipmi_pef_destroy(pet->pef, NULL, NULL);
	pet->pef = NULL;
	pet_op_done(pet);
	goto out;
    } else {
	unsigned char data[1];

	if (!pet->pef_err && pet->changed_pef) {
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
    pet_unlock(pet);
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
	return -1;
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

    pet_lock(pet);
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
    pet_unlock(pet);
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
    unsigned int  i;

    pet_lock(pet);
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
	pet->changed_pef = 1;
    } else {
	rv = pef_next_config(pet);
	if (rv) {
	    pef_op_done(pet, rv);
	    goto out;
	}
    }

    pet_unlock(pet);
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

    pet_lock(pet);
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

    pet_unlock(pet);
 out:
    return;
}

static void
pef_alloced(ipmi_pef_t *pef, int err, void *cb_data)
{
    ipmi_pet_t    *pet = cb_data;
    unsigned char data[1];
    int           rv;

    pet_lock(pet);
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

    pet_unlock(pet);
 out:
    return;
}

static int
start_pet_setup(ipmi_mc_t  *mc,
		ipmi_pet_t *pet)
{
    int  rv = 0;

    pet_lock(pet);

    if (pet->in_progress) {
	pet_unlock(pet);
	return EAGAIN;
    }

    pet->pet = pet;
    pet->pef_lock_broken = 0;
    pet->pef_err = 0;
    pet->changed_pef = 0;
    pet->lanparm_lock_broken = 0;
    pet->lanparm_err = 0;
    pet->changed_lanparm = 0;

    pet->pef_check_pos = 0;
    pet->in_progress++;
    pet_get_nolock(pet);
    rv = ipmi_pef_alloc(mc, pef_alloced, pet, &pet->pef);
    if (rv) {
	pet->in_progress--;
	pet_put_nolock(pet);
	ipmi_log(IPMI_LOG_WARNING,
		 "start_pet_setup: Unable to allocate pef: 0x%x", rv);
	goto out;
    }

    /* Now that we have the channel, set up the lan parms. */
    pet->lanparm_check_pos = 0;
    rv = ipmi_lanparm_alloc(mc, pet->channel, &(pet->lanparm));
    if (rv) {
	ipmi_log(IPMI_LOG_WARNING,
		 "start_pet_setup: Unable to allocate lanparm: 0x%x",
		 rv);
    } else {
	pet->in_progress++;
	pet_get_nolock(pet);
	rv = ipmi_lanparm_get_parm(pet->lanparm,
				   IPMI_LANPARM_DEST_TYPE,
				   pet->lan_dest_sel,
				   0,
				   lanparm_got_config,
				   pet);
	if (rv) {
	    pet->in_progress--;
	    pet_put_nolock(pet);
	    ipmi_log(IPMI_LOG_WARNING,
		     "start_pet_setup: Unable to get dest type: 0x%x",
		     rv);
	    ipmi_lanparm_destroy(pet->lanparm, NULL, NULL);
	    pet->lanparm = NULL;
	}
    }
    rv = 0; /* We continue with the PEF run, even if the lanparm fails. */

 out:
    pet_unlock(pet);
    return rv;
}

int
ipmi_pet_create_mc(ipmi_mc_t        *mc,
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
    ipmi_pet_t         *pet;
    int                rv;
    os_handler_t       *os_hnd;
    char               domain_name[IPMI_MC_NAME_LEN];
    ipmi_domain_t      *domain = ipmi_mc_get_domain(mc);
    ipmi_domain_attr_t *attr;
    locked_list_t      *pets;

    rv = ipmi_domain_register_attribute(domain, IPMI_PET_ATTR_NAME,
					pet_attr_init, pet_attr_destroy, NULL,
					&attr);
    if (rv)
	return rv;
    pets = ipmi_domain_attr_get_data(attr);

    pet = ipmi_mem_alloc(sizeof(*pet));
    if (!pet) {
	ipmi_domain_attr_put(attr);
	return ENOMEM;
    }
    memset(pet, 0, sizeof(*pet));

    ipmi_domain_get_name(domain, domain_name, sizeof(domain_name));
    snprintf(pet->name, sizeof(pet->name), "%s.%d", domain_name,
	     ipmi_domain_get_unique_num(domain));
    pet->refcount = 1;
    pet->in_list = 1;
    pet->mc = ipmi_mc_convert_to_id(mc);
    pet->domain = ipmi_domain_convert_to_id(domain);
    pet->channel = channel;
    pet->ip_addr = ip_addr;
    pet->policy_num = policy_num;
    pet->eft_sel = eft_sel;
    pet->apt_sel = apt_sel;
    pet->lan_dest_sel = lan_dest_sel;
    pet->done = done;
    pet->cb_data = cb_data;
    memcpy(pet->mac_addr, mac_addr, sizeof(pet->mac_addr));
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

    /* Start a timer for this PET to periodically check it. */
    pet->timer_info = ipmi_mem_alloc(sizeof(*(pet->timer_info)));
    if (!pet->timer_info) {
	rv = ENOMEM;
	goto out_err;
    }
    pet->timer_info->cancelled = 0;
    pet->timer_info->os_hnd = os_hnd;
    pet->timer_info->pet = pet;
    pet->timer_info->running = 0;
    pet->timer_info->lock = NULL;
    rv = os_hnd->alloc_timer(os_hnd, &pet->timer);
    if (rv)
	goto out_err;

    rv = ipmi_create_lock_os_hnd(os_hnd, &pet->timer_info->lock);
    if (rv)
	goto out_err;

    if (! locked_list_add(pets, pet, NULL)) {
	rv = ENOMEM;
	goto out_err;
    }

    ipmi_domain_attr_put(attr);

    rv = start_pet_setup(mc, pet);
    if (rv)
	goto out_err;

    if (ret_pet)
	*ret_pet = pet;

    return 0;

 out_err:
    locked_list_remove(pets, pet, NULL);
    ipmi_domain_attr_put(attr);
    if (pet->timer_info) {
	if (pet->timer) {
	    if (os_hnd->stop_timer(os_hnd, pet->timer) == 0) {
		if (pet->timer_info->lock)
		    ipmi_destroy_lock(pet->timer_info->lock);
		os_hnd->free_timer(os_hnd, pet->timer);
		ipmi_mem_free(pet->timer_info);
	    } else {
		pet->timer_info->cancelled = 1;
	    }
	} else
	    ipmi_mem_free(pet->timer_info);
    }
    ipmi_mem_free(pet);
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
    ipmi_system_interface_addr_t si;
    ipmi_mc_t                    *mc;
    int                          rv;

    si.addr_type = IPMI_SYSTEM_INTERFACE_ADDR_TYPE;
    si.channel = connection;
    si.lun = 0;

    mc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &si, sizeof(si));
    if ((!mc)  && (connection == 0)) {
	/* If the specific connection doesn't exist and the connection
	   is 0, use the BMC channel. */
	si.channel = IPMI_BMC_CHANNEL;
	mc = _ipmi_find_mc_by_addr(domain, (ipmi_addr_t *) &si,
				   sizeof(si));
    }

    if (!mc)
	return EINVAL;

    rv = ipmi_pet_create_mc(mc,
			    channel,
			    ip_addr,
			    mac_addr,
			    eft_sel,
			    policy_num,
			    apt_sel,
			    lan_dest_sel,
			    done,
			    cb_data,
			    ret_pet);
    _ipmi_mc_put(mc);

    return rv;
}

static void
rescan_pet_mc(ipmi_mc_t *mc, void *cb_data)
{
    pet_timer_t *timer_info = cb_data;
    ipmi_pet_t  *pet = timer_info->pet;

    timer_info->err = start_pet_setup(mc, pet);
}

static void
rescan_pet(void *cb_data, os_hnd_timer_id_t *id)
{
    pet_timer_t    *timer_info = cb_data;
    ipmi_pet_t     *pet;
    int            rv;
    struct timeval timeout;

    ipmi_lock(timer_info->lock);
    if (timer_info->cancelled) {
	ipmi_unlock(timer_info->lock);
	timer_info->os_hnd->free_timer(timer_info->os_hnd, id);
	ipmi_destroy_lock(timer_info->lock);
	ipmi_mem_free(timer_info);
	return;
    }
    pet = timer_info->pet;
    pet->timer_info->running = 0;
    pet_get(pet);

    timer_info->err = 0;
    rv = ipmi_mc_pointer_cb(pet->mc, rescan_pet_mc, timer_info);
    if (!rv)
	rv = timer_info->err;

    if (rv) {
	os_handler_t *os_hnd = timer_info->os_hnd;
	/* Got an error, just restart the timer */
	timeout.tv_sec = PET_TIMEOUT_SEC;
	timeout.tv_usec = 0;
	os_hnd->start_timer(os_hnd, pet->timer, &timeout, rescan_pet,
			    pet->timer_info);
	pet->timer_info->running = 1;
    }

    ipmi_unlock(timer_info->lock);
}

int
ipmi_pet_destroy(ipmi_pet_t       *pet,
		 ipmi_pet_done_cb done,
		 void             *cb_data)

{
    pet_lock(pet);
    if (pet->in_list) {
	ipmi_domain_attr_t *attr;
	locked_list_t      *pets;
	int                rv;

	pet->in_list = 0;
	rv = ipmi_domain_id_find_attribute(pet->domain,
					   IPMI_PET_ATTR_NAME, &attr);
	if (!rv) {
	    pet_unlock(pet);
	
	    pets = ipmi_domain_attr_get_data(attr);

	    locked_list_remove(pets, pet, NULL);
	    ipmi_domain_attr_put(attr);
	    pet_lock(pet);
	}
    }

    pet->destroyed = 1;
    pet->destroy_done = done;
    pet->destroy_cb_data = cb_data;
    pet_unlock(pet);

    pet_put(pet);
    return 0;
}

int
ipmi_pet_get_name(ipmi_pet_t *pet, char *name, int length)
{
    int  slen;

    if (length <= 0)
	return 0;

    /* Never changes, no lock needed. */
    slen = strlen(pet->name);
    if (slen == 0) {
	if (name)
	    *name = '\0';
	goto out;
    }

    if (name) {
	memcpy(name, pet->name, slen);
	name[slen] = '\0';
    }
 out:
    return slen;
}

typedef struct iterate_pets_info_s
{
    ipmi_pet_ptr_cb handler;
    void            *cb_data;
} iterate_pets_info_t;

static int
pets_handler(void *cb_data, void *item1, void *item2)
{
    iterate_pets_info_t *info = cb_data;
    info->handler(item1, info->cb_data);
    pet_put(item1);
    return LOCKED_LIST_ITER_CONTINUE;
}

static int
pets_prefunc(void *cb_data, void *item1, void *item2)
{
    pet_get(item1);
    return LOCKED_LIST_ITER_CONTINUE;
}

void
ipmi_pet_iterate_pets(ipmi_domain_t   *domain,
		      ipmi_pet_ptr_cb handler,
		      void            *cb_data)
{
    iterate_pets_info_t info;
    ipmi_domain_attr_t  *attr;
    locked_list_t       *pets;
    int                 rv;

    rv = ipmi_domain_find_attribute(domain, IPMI_PET_ATTR_NAME,
				    &attr);
    if (rv)
	return;
    pets = ipmi_domain_attr_get_data(attr);

    info.handler = handler;
    info.cb_data = cb_data;
    locked_list_iterate_prefunc(pets, pets_prefunc, pets_handler, &info);
    ipmi_domain_attr_put(attr);
}

ipmi_mcid_t
ipmi_pet_get_mc_id(ipmi_pet_t *pet)
{
    return pet->mc;
}

unsigned int
ipmi_pet_get_channel(ipmi_pet_t *pet)
{
    return pet->channel;
}

struct in_addr *
ipmi_pet_get_ip_addr(ipmi_pet_t *pet, struct in_addr *ip_addr)
{
    memcpy(ip_addr, &pet->ip_addr, sizeof(*ip_addr));
    return ip_addr;
}

unsigned char *
ipmi_pet_get_mac_addr(ipmi_pet_t *pet, unsigned char mac_addr[6])
{
    memcpy(mac_addr, pet->mac_addr, 6);
    return mac_addr;
}

unsigned int
ipmi_pet_get_eft_sel(ipmi_pet_t *pet)
{
    return pet->eft_sel;
}

unsigned int
ipmi_pet_get_policy_num(ipmi_pet_t *pet)
{
    return pet->policy_num;
}

unsigned int
ipmi_pet_get_apt_sel(ipmi_pet_t *pet)
{
    return pet->apt_sel;
}

unsigned int
ipmi_pet_get_lan_dest_sel(ipmi_pet_t *pet)
{
    return pet->lan_dest_sel;
}
