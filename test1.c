/*
 * test1.c
 *
 * MontaVista IPMI test code
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002 MontaVista Software Inc.
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
#include <stdlib.h>
#include <string.h>
#include <malloc.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>

#include <ipmi/ipmiif.h>
#include <ipmi/ipmi_sel.h>
#include <ipmi/ipmi_smi.h>
#include <ipmi/ipmi_err.h>
#include <ipmi/ipmi_auth.h>
#include <ipmi/ipmi_lan.h>
#include <ipmi/selector.h>

selector_t *sel;

void
report_error(char *name, int err)
{
    if (IPMI_IS_OS_ERR(err)) {
	fprintf(stderr, "%s: %s\n", name, strerror(IPMI_GET_OS_ERR(err)));
    } else {
	fprintf(stderr, "%s: IPMI Error %2.2x\n",
		name, IPMI_GET_IPMI_ERR(err));
    }
}

struct os_hnd_fd_id_s
{
    int             fd;
    void            *cb_data;
    os_data_ready_t data_ready;
};

static void
fd_handler(int fd, void *data)
{
    os_hnd_fd_id_t *fd_data = (os_hnd_fd_id_t *) data;

    fd_data->data_ready(fd, fd_data->cb_data, fd_data);
}

static int
add_fd(os_handler_t    *handler,
       int             fd,
       os_data_ready_t data_ready,
       void            *cb_data,
       os_hnd_fd_id_t  **id)
{
    os_hnd_fd_id_t *fd_data;

    fd_data = malloc(sizeof(*fd_data));
    if (!fd_data)
	return ENOMEM;

    fd_data->fd = fd;
    fd_data->cb_data = cb_data;
    fd_data->data_ready = data_ready;
    sel_set_fd_handlers(sel, fd, fd_data, fd_handler, NULL, NULL);
    sel_set_fd_read_handler(sel, fd, SEL_FD_HANDLER_ENABLED);
    sel_set_fd_write_handler(sel, fd, SEL_FD_HANDLER_DISABLED);
    sel_set_fd_except_handler(sel, fd, SEL_FD_HANDLER_DISABLED);

    *id = fd_data;
    return 0;
}

static int
remove_fd(os_handler_t   *handler, os_hnd_fd_id_t *fd_data)
{
    sel_clear_fd_handlers(sel, fd_data->fd);
    sel_set_fd_read_handler(sel, fd_data->fd, SEL_FD_HANDLER_DISABLED);
    free(fd_data);
    return 0;
}

struct os_hnd_timer_id_s
{
    void           *cb_data;
    os_timed_out_t timed_out;
    sel_timer_t    *timer;
    int            running;
};

static void
free_timer(os_hnd_timer_id_t *timer)
{
    sel_free_timer(timer->timer);
    free(timer);
}

static void
timer_handler(selector_t  *sel,
	      sel_timer_t *timer,
	      void        *data)
{
    os_hnd_timer_id_t *timer_data = (os_hnd_timer_id_t *) data;

    timer_data->running = 0;
    timer_data->timed_out(timer_data->cb_data, timer_data);

    /* The timer might have been restarted. */
    if (!timer_data->running)
	free_timer(timer_data);
}

static int
add_timer(os_handler_t      *handler,
	  struct timeval    *timeout,
	  os_timed_out_t    timed_out,
	  void              *cb_data,
	  os_hnd_timer_id_t **id)
{
    os_hnd_timer_id_t *timer_data;
    int               rv;
    struct timeval    now;

    timer_data = malloc(sizeof(*timer_data));
    if (!timer_data)
	return ENOMEM;

    timer_data->running = 1;
    timer_data->cb_data = cb_data;
    timer_data->timed_out = timed_out;

    gettimeofday(&now, NULL);
    now.tv_sec += timeout->tv_sec;
    now.tv_usec += timeout->tv_usec;
    while (now.tv_usec >= 1000000) {
	now.tv_usec -= 1000000;
	now.tv_sec += 1;
    }

    rv = sel_alloc_timer(sel, timer_handler, timer_data, &(timer_data->timer));
    if (rv) {
	free(timer_data);
	return rv;
    }

    rv = sel_start_timer(timer_data->timer, &now);
    if (rv) {
	free_timer(timer_data);
	return rv;
    }

    *id = timer_data;
    return 0;
}

static void
restart_timer(os_handler_t      *handler,
	      os_hnd_timer_id_t *id,
	      struct timeval    *timeout)
{
    struct timeval    now;


    gettimeofday(&now, NULL);
    now.tv_sec += timeout->tv_sec;
    now.tv_usec += timeout->tv_usec;
    while (now.tv_usec >= 1000000) {
	now.tv_usec -= 1000000;
	now.tv_sec += 1;
    }

    id->running = 1;

    /* This really can't fail, it can only fail if the timer is already
       running, and that won't be the case here. */
    sel_start_timer(id->timer, &now);
}

static int
remove_timer(os_handler_t *handler, os_hnd_timer_id_t *timer_data)
{
    free_timer(timer_data);
    return 0;
}

static int
get_random(os_handler_t *handler, void *data, unsigned int len)
{
    int fd = open("/dev/random", O_RDONLY);
    int rv;

    if (fd == -1)
	return errno;

    rv = read(fd, data, len);

    close(fd);
    return rv;
}

static void
sui_log(os_handler_t *handler,
	char         *format,
	...)
{
    va_list ap;

    va_start(ap, format);
    vprintf(format, ap);
    va_end(ap);
}

static void
sui_vlog(os_handler_t *handler,
	 char         *format,
	 va_list      ap)
{
    vprintf(format, ap);
}

os_handler_t ipmi_cb_handlers =
{
    .add_fd_to_wait_for = add_fd,
    .remove_fd_to_wait_for = remove_fd,
    .add_timer = add_timer,
    .remove_timer = remove_timer,
    .restart_timer = restart_timer,
    .create_lock = NULL,
    .destroy_lock = NULL,
    .lock = NULL,
    .unlock = NULL,
    .get_random = get_random,
    .log = sui_log,
    .vlog = sui_vlog
};


ipmi_mc_t *cb_mc;

void got_sels(ipmi_sel_info_t *sel,
	      int             err,
	      int             changed,
	      unsigned int    count,
	      void            *cb_data)
{
    int rv;
    int i, j;

    if (err) {
	report_error("ipmi sel fetch", err);
	exit(1);
    }

    printf("SEL Changed = %d, count = %d\n", changed, count);
    for (i=0; i<count; i++) {
	ipmi_sel_t rsel;

	rv = ipmi_get_sel_by_index(sel, i, &rsel);
	if (rv) {
	    report_error("ipmi_get_sel_by_index", err);
	    exit(1);
	}
	printf("sel %d (%d):\n ", i, rsel.record_id);
	for (j=0; j<13; j++) {
	    printf(" %2.2x", rsel.data[j]);
	}
	printf("\n");
    }

    rv = ipmi_sel_destroy(sel, NULL, NULL);
    if (rv) {
	report_error("ipmi_sel_destroy", rv);
	exit(1);
    }

#if 0
    ipmi_mc_t *mc = (ipmi_mc_t *) cb_data;
    rv = ipmi_close_connection(mc, NULL, NULL);
    if (rv) {
	report_error("ipmi_close_connection", rv);
	exit(1);
    }
#endif
}

void got_sdrs(ipmi_sdr_info_t *sdr,
	      int             err,
	      int             changed,
	      unsigned int    count,
	      void            *cb_data)
{
    ipmi_mc_t       *mc = cb_data;
    int             rv;
    int             i, j;
    ipmi_sel_info_t *sel;

    if (err) {
	report_error("ipmi sdr fetch", err);
	exit(1);
    }

    printf("SDR Changed = %d, count = %d\n", changed, count);
    for (i=0; i<count; i++) {
	ipmi_sdr_t rsdr;

	rv = ipmi_get_sdr_by_index(sdr, i, &rsdr);
	if (rv) {
	    report_error("ipmi_get_sdr_by_index", err);
	    exit(1);
	}
	printf("sdr %d (%d): version %d.%d, type=%d, length=%d",
	       i, rsdr.record_id, rsdr.major_version, rsdr.minor_version,
	       rsdr.type, rsdr.length);
	for (j=0; j<rsdr.length; j++) {
	    if ((j % 16) == 0) {
		printf("\n ");
	    }
	    printf(" %2.2x", rsdr.data[j]);
	}
	printf("\n");
    }

    rv = ipmi_sdr_destroy(sdr, NULL, NULL);
    if (rv) {
	report_error("ipmi_sdr_destroy", rv);
	exit(1);
    }

    rv = ipmi_sel_alloc(mc, 0, &sel);
    if (rv) {
	report_error("ipmi_sel_alloc", rv);
	exit(1);
    }

    rv = ipmi_sel_get(sel, got_sels, mc);
    if (rv) {
	report_error("ipmi_sel_get", rv);
    }
}

static void
put_float(int err, double val, char *str)
{
    if (err)
	printf(" %s: could not fetch, err = %d\n", str, err);
    else
	printf(" %s = %f\n", str, val);
}

static void
sensor_change(enum ipmi_update_e op,
	      ipmi_entity_t      *ent,
	      ipmi_sensor_t      *sensor,
	      void               *cb_data)
{
    int id, instance;
    int lun, num;
    char name[33];
    double val;
    int rv;
    int i;

    id = ipmi_entity_get_entity_id(ent);
    instance = ipmi_entity_get_entity_instance(ent);
    ipmi_sensor_get_num(sensor, &lun, &num);
    switch (op) {
	case ADDED:
	    printf("Sensor added: %d.%d.%d.%d\n", id, instance, lun, num);
	    ipmi_sensor_get_id(sensor, name, 33);
	    printf(" id=%s\n", name);
	    printf(" type=0x%2.2x\n", ipmi_sensor_get_sensor_type(sensor));
	    printf(" reading_type=0x%2.2x\n", ipmi_sensor_get_event_reading_type(sensor));
	    for (i=0; i<16; i++) {
		
	    }
	    printf(" analog_data_format=%d\n", ipmi_sensor_get_analog_data_format(sensor));
	    printf(" linearization = %d\n", ipmi_sensor_get_linearization(sensor));
	    printf(" raw sensor max = %d\n", ipmi_sensor_get_raw_sensor_max(sensor));
	    printf(" raw sensor min = %d\n", ipmi_sensor_get_raw_sensor_max(sensor));
	    printf(" raw upper non-recoverable threshold = %d\n", ipmi_sensor_get_raw_upper_non_recoverable_threshold(sensor));
	    printf(" raw upper critical threshold = %d\n", ipmi_sensor_get_raw_upper_critical_threshold(sensor));
	    printf(" raw upper non-critical threshold = %d\n", ipmi_sensor_get_raw_upper_non_critical_threshold(sensor));
	    printf(" raw lower non-recoverable threshold = %d\n", ipmi_sensor_get_raw_lower_non_recoverable_threshold(sensor));
	    printf(" raw lower critical threshold = %d\n", ipmi_sensor_get_raw_lower_critical_threshold(sensor));
	    printf(" raw lower non-critical threshold = %d\n", ipmi_sensor_get_raw_lower_non_critical_threshold(sensor));
	    printf(" raw m = %d\n", ipmi_sensor_get_raw_m(sensor, 0));
	    printf(" raw b = %d\n", ipmi_sensor_get_raw_b(sensor, 0));
	    printf(" raw r_exp = %d\n", ipmi_sensor_get_raw_r_exp(sensor, 0));
	    printf(" raw b_exp = %d\n", ipmi_sensor_get_raw_b_exp(sensor, 0));
	    rv = ipmi_sensor_get_nominal_reading(sensor, &val);
	    put_float(rv, val, "nominal");
	    rv = ipmi_sensor_get_normal_min(sensor, &val);
	    put_float(rv, val, "normal min");
	    rv = ipmi_sensor_get_normal_max(sensor, &val);
	    put_float(rv, val, "normal max");
	    rv = ipmi_sensor_get_sensor_min(sensor, &val);
	    put_float(rv, val, "sensor min");
	    rv = ipmi_sensor_get_sensor_max(sensor, &val);
	    put_float(rv, val, "sensor max");
	    rv = ipmi_sensor_get_upper_non_recoverable_threshold(sensor, &val);
	    put_float(rv, val, "upper non-recoverable threshold");
	    rv = ipmi_sensor_get_upper_critical_threshold(sensor, &val);
	    put_float(rv, val, "upper critical threshold");
	    rv = ipmi_sensor_get_upper_non_critical_threshold(sensor, &val);
	    put_float(rv, val, "upper non-critical threshold");
	    rv = ipmi_sensor_get_lower_non_recoverable_threshold(sensor, &val);
	    put_float(rv, val, "lower non-recoverable threshold");
	    rv = ipmi_sensor_get_lower_critical_threshold(sensor, &val);
	    put_float(rv, val, "lower critical threshold");
	    rv = ipmi_sensor_get_lower_non_critical_threshold(sensor, &val);
	    put_float(rv, val, "lower non-critical threshold");
	    break;
	case DELETED:
	    printf("Sensor deleted: %d.%d.%d.%d\n", id, instance, lun, num);
	    break;
	case CHANGED:
	    printf("Sensor changed: %d.%d.%d.%d\n", id, instance, lun, num);
	    break;
    }
}

static void
entity_presence_handler(ipmi_entity_t *entity,
			int           present,
			void          *cb_data)
{
    int id, instance;

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    printf("---Entity %d.%d, presence is %d\n", id, instance, present);
}

static void
entity_change(enum ipmi_update_e op,
	      ipmi_mc_t          *bmc,
	      ipmi_entity_t      *entity,
	      void               *cb_data)
{
    int rv;
    int id, instance;

    id = ipmi_entity_get_entity_id(entity);
    instance = ipmi_entity_get_entity_instance(entity);
    switch (op) {
	case ADDED:
	    printf("Entity added: %d.%d\n", id, instance);
	    rv = ipmi_entity_set_sensor_update_handler(entity,
						       sensor_change,
						       entity);
	    if (rv) {
		report_error("ipmi_entity_set_sensor_update_handler", rv);
		exit(1);
	    }
	    rv = ipmi_entity_set_presence_handler(entity,
						  entity_presence_handler,
						  NULL);
	    if (rv) {
		report_error("ipmi_entity_set_presence_handler", rv);
		exit(1);
	    }
	    break;
	case DELETED:
	    printf("Entity deleted: %d.%d\n", id, instance);
	    break;
	case CHANGED:
	    printf("Entity changed: %d.%d\n", id, instance);
	    break;
    }
}

void
setup_done(ipmi_mc_t *mc,
	   void      *user_data,
	   int       err)
{
    ipmi_sdr_info_t *sdr;
    int             rv;


    cb_mc = mc;

    if (err) {
	report_error("setup_done", err);
	exit(1);
    }

    rv = ipmi_bmc_set_entity_update_handler(mc, entity_change, mc);
    if (rv) {
	report_error("ipmi_bmc_set_entity_update_handler", rv);
	exit(1);
    }

    rv = ipmi_sdr_alloc(mc, 0, 0, &sdr);
    if (rv) {
	report_error("ipmi_sdr_alloc", rv);
	exit(1);
    }

    rv = ipmi_sdr_fetch(sdr, got_sdrs, mc);
    if (rv) {
	report_error("ipmi_sdr_fetch", rv);
	exit(1);
    }
}

static enum { SMI_MODE, LAN_MODE } mode;
int smi_intf;

struct in_addr lan_addr;
int            lan_port;
int            authtype;
int            privilege;
char           username[17];
char           password[17];

void
check_sel(void)
{
    int rv;

    rv = sel_alloc_selector(&sel);
    if (rv) {
	report_error("sel_alloc_selector", rv);
	exit(1);
    }

    if (mode == SMI_MODE) {
	rv = ipmi_smi_setup_con(0, &ipmi_cb_handlers, sel, setup_done, NULL);
	if (rv) {
	    report_error("ipmi_smi_setup_con", rv);
	    exit(1);
	}
    } else if (mode == LAN_MODE) {
	rv = ipmi_lan_setup_con(lan_addr, lan_port,
				authtype, privilege,
				username, strlen(username),
				password, strlen(password),
				&ipmi_cb_handlers, sel, setup_done, NULL);
	if (rv) {
	    report_error("ipmi_lan_setup_con", rv);
	    exit(1);
	}
    } else {
	return;
    }

    sel_select_loop(sel);
}

extern unsigned int __ipmi_log_mask;
int
main(int argc, char *argv[])
{
    if (argc < 2) {
	fprintf(stderr, "Not enough arguments\n");
	exit(1);
    }
__ipmi_log_mask = 0xffffffff;
    if (strcmp(argv[1], "smi") == 0) {
	if (argc < 3) {
	    fprintf(stderr, "Not enough arguments\n");
	    exit(1);
	}
	mode = SMI_MODE;
	smi_intf = atoi(argv[2]);
    } else if (strcmp(argv[1], "lan") == 0) {
	struct hostent *ent;
	if (argc < 8) {
	    fprintf(stderr, "Not enough arguments\n");
	    exit(1);
	}
	ent = gethostbyname(argv[2]);
	if (!ent) {
	    fprintf(stderr, "gethostbyname failed: %s\n", strerror(h_errno));
	    exit(1);
	}
	memcpy(&lan_addr, ent->h_addr_list[0], ent->h_length);
	lan_port = atoi(argv[3]);

	if (strcmp(argv[4], "none") == 0) {
	    authtype = IPMI_AUTHTYPE_NONE;
	} else if (strcmp(argv[4], "md2") == 0) {
	    authtype = IPMI_AUTHTYPE_MD2;
	} else if (strcmp(argv[4], "md5") == 0) {
	    authtype = IPMI_AUTHTYPE_MD5;
	} else if (strcmp(argv[4], "straight") == 0) {
	    authtype = IPMI_AUTHTYPE_STRAIGHT;
	} else {
	    fprintf(stderr, "Invalid authtype: %s\n", argv[4]);
	    exit(1);
	}

	if (strcmp(argv[5], "callback") == 0) {
	    privilege = IPMI_PRIVILEGE_CALLBACK;
	} else if (strcmp(argv[5], "user") == 0) {
	    privilege = IPMI_PRIVILEGE_USER;
	} else if (strcmp(argv[5], "operator") == 0) {
	    privilege = IPMI_PRIVILEGE_OPERATOR;
	} else if (strcmp(argv[5], "admin") == 0) {
	    privilege = IPMI_PRIVILEGE_ADMIN;
	} else {
	    fprintf(stderr, "Invalid privilege: %s\n", argv[5]);
	    exit(1);
	}

	memset(username, 0, sizeof(username));
	memset(password, 0, sizeof(password));
	strncpy(username, argv[6], 16);
	username[16] = '\0';
	strncpy(password, argv[7], 16);
	password[16] = '\0';
	mode = LAN_MODE;
    } else {
	fprintf(stderr, "Invalid mode\n");
	exit(1);
    }

    ipmi_init(&ipmi_cb_handlers);

    check_sel();
    return 0;
}
