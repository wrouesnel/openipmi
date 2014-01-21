/*
 * marvel_mod.c
 *
 * Marvell specific modules for handling BMC and MC functions.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2012,2013 MontaVista Software Inc.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * Lesser General Public License (GPL) Version 2 or the modified BSD
 * license below.  The following disclamer applies to both licenses:
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
 * GNU Lesser General Public Licence
 *
 *  This program is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public License
 *  as published by the Free Software Foundation; either version 2 of
 *  the License, or (at your option) any later version.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this program; if not, write to the Free
 *  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Modified BSD Licence
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   1. Redistributions of source code must retain the above copyright
 *      notice, this list of conditions and the following disclaimer.
 *   2. Redistributions in binary form must reproduce the above
 *      copyright notice, this list of conditions and the following
 *      disclaimer in the documentation and/or other materials provided
 *      with the distribution.
 *   3. The name of the author may not be used to endorse or promote
 *      products derived from this software without specific prior
 *      written permission.
 */

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <signal.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <semaphore.h>

#include <OpenIPMI/ipmi_msgbits.h>
#include <OpenIPMI/ipmi_bits.h>
#include <OpenIPMI/serv.h>

#include "wiw.h"

#define PVERSION "2.0.12"

#define NUM_BOARDS 6

#define CHASSIS_FRU_SIZE 1024
#define BOARD_FRU_SIZE 2048

#define BOARD_TEMP_SHUTDOWN 105
#define SWITCH_TEMP_SHUTDOWN 115
#define FRONT_TEMP_SHUTDOWN 50

#define MARVELL_SEMI_ISREAL_IANA	20495
#define DISABLE_NETWORK_SRVC_CMD	1
#define RELOAD_BOARD_FRU_CMD		2
#define SET_ALL_FANS_DUTY_CMD		3
#define GET_ALL_FANS_DUTY_CMD		4

#define BOARD_FRU_FILE "/etc/ipmi/axp_board_fru"
#define COLD_POWER_FILE "/var/lib/ipmi_sim_coldpower"
#define RESET_REASON_FILE "/var/lib/reset_reason"
#define RESET_REASON_UNKNOWN 0
#define RESET_REASON_COLD_BOOT 1
#define RESET_REASON_WARM_BOOT 2
static int init_complete;

#define GPIODIR "/sys/class/astgpio/GPIO"

#define COLD_POWER_UP_IO "/sys/class/astgpio/ColdBoot"
static unsigned int cold_power_up = 1;

/*
 * Set debugging with bits:
 * bit 0 - power
 * bit 1 - sensor reading
 * bit 2 - sensor writing
 * bit 3 - fan
 */
static unsigned int debug;

/* 1 second poll time */
static unsigned int poll_time = 2000000;

static lmc_data_t *bmc_mc;

/* Set the file to "0" to enable reset */
#define BOARD_RESET_ON 0
#define BOARD_RESET_OFF 1
static const char *trg_reset[NUM_BOARDS] =
{
    GPIODIR "H0",
    GPIODIR "H1",
    GPIODIR "H2",
    GPIODIR "H3",
    GPIODIR "H4",
    GPIODIR "H5"
};

/* Set the file to "1" to power on, "0" to power off. */
#define BOARD_POWER_ON 1
#define BOARD_POWER_OFF 0
static const char *trg_power[NUM_BOARDS] =
{
    GPIODIR "D6",
    GPIODIR "D7",
    GPIODIR "B0",
    GPIODIR "B1",
    GPIODIR "B2",
    GPIODIR "B3"
};

/* Will contain "0" if present, "1" if not present. */
#define BOARD_PRESENT 0
#define BOARD_ABSENT 1
static const char *trg_present[NUM_BOARDS] =
{
    GPIODIR "C0",
    GPIODIR "C1",
    GPIODIR "C2",
    GPIODIR "C3",
    GPIODIR "C4",
    GPIODIR "C5",
};

static int simulate_board_absent[NUM_BOARDS];

/* Set this to zero to request that the board power off.  */
#define BOARD_OFF_REQUEST_ON 0
#define BOARD_OFF_REQUEST_OFF 1
static const char *pow_off_request[NUM_BOARDS] =
{
    GPIODIR "A6",
    GPIODIR "A7",
    GPIODIR "I4",
    GPIODIR "I5",
    GPIODIR "I6",
    GPIODIR "I7"
};

/* The board will set the value to 0 when it is ready to power off.  */
#define BOARD_OFF_READY 0
#define BOARD_OFF_NOT_READY 1
static const char *pow_off_ready[NUM_BOARDS] =
{
    GPIODIR "A0",
    GPIODIR "A1",
    GPIODIR "A2",
    GPIODIR "A3",
    GPIODIR "G4",
    GPIODIR "G5"
};


#define I2CDIR "/sys/class/i2c-adapter/i2c-"

struct eeprom {
    unsigned char addr;
    const char *part;
    const char *dev;
    unsigned int size;
};

static struct board_i2c_info
{
    const char *add_dev;
    struct eeprom fru;
} const board_i2c[NUM_BOARDS] =
{
    {
	.add_dev = I2CDIR "1/new_device",
	.fru = {
	    .addr = 0x50,
	    .part = "24c64",
	    .dev = I2CDIR "1/1-0050/at24c64",
	    .size = BOARD_FRU_SIZE
	},
    },
    {
	.add_dev = I2CDIR "2/new_device",
	.fru = {
	    .addr = 0x50,
	    .part = "24c64",
	    .dev = I2CDIR "2/2-0050/at24c64",
	    .size = BOARD_FRU_SIZE
	},
    },
    {
	.add_dev = I2CDIR "3/new_device",
	.fru = {
	    .addr = 0x50,
	    .part = "24c64",
	    .dev = I2CDIR "3/3-0050/at24c64",
	    .size = BOARD_FRU_SIZE
	},
    },
    {
	.add_dev = I2CDIR "4/new_device",
	.fru = {
	    .addr = 0x50,
	    .part = "24c64",
	    .dev = I2CDIR "4/4-0050/at24c64",
	    .size = BOARD_FRU_SIZE
	},
    },
    {
	.add_dev = I2CDIR "5/new_device",
	.fru = {
	    .addr = 0x50,
	    .part = "24c64",
	    .dev = I2CDIR "5/5-0050/at24c64",
	    .size = BOARD_FRU_SIZE
	},
    },
    {
	.add_dev = I2CDIR "6/new_device",
	.fru = {
	    .addr = 0x50,
	    .part = "24c64",
	    .dev = I2CDIR "6/6-0050/at24c64",
	    .size = BOARD_FRU_SIZE
	},
    },
};

static struct board_i2c_info *chassis_i2c;

/* For older systems (before DVT2) */
static struct board_i2c_info chassis_i2c_old = 
{
    .add_dev = I2CDIR "7/new_device",
    .fru = {
	.addr = 0x54,
	.part = "24c128",
	.dev = I2CDIR "7/7-0054/at24c128",
	.size = CHASSIS_FRU_SIZE
    }
};

/* For newer systems (DVT2 and later) */
static struct board_i2c_info chassis_i2c_new = 
{
    .add_dev = I2CDIR "0/new_device",
    .fru = {
	.addr = 0x54,
	.part = "24c128",
	.dev = I2CDIR "0/0-0051/at24c128",
	.size = CHASSIS_FRU_SIZE
    }
};

static struct board_info {
    sys_data_t *sys;

    lmc_data_t *mc;
    unsigned char num;
    char present;
    char fru_good;
    unsigned char fru[BOARD_FRU_SIZE];
    struct timeval button_press_time;
    unsigned int power_off_countdown;
    char button_pressed;
    char waiting_power_off;

    volatile char fru_data_ready_for_handling;

    /*
     * Tracks the state of the power request line, request happens
     * on a 1->0 transition.
     */
    char last_power_request;
} boards[NUM_BOARDS];

struct timeval last_board_power_on;

static unsigned char chassis_fru[CHASSIS_FRU_SIZE];
static unsigned int chassis_iuse;
static unsigned int chassis_iuse_len;
static unsigned int chassis_chinfo;
static unsigned int chassis_chinfo_len;
static unsigned int chassis_brdinfo;
static unsigned int chassis_brdinfo_len;

/* Offset from beginning of chassis info area */
static unsigned int sernum_offset;
static unsigned int sernum_offset2;
static unsigned int sernum_len;
static unsigned int sysmac_offset;

/* Pieces of the serial number and MAC we need for generating board info */
static unsigned char sernum[10];
static unsigned char sysmac[17];

static const unsigned char board_ipmb[NUM_BOARDS] = { 1, 2, 3, 4, 5, 6 };

static int disable_wdt;
static int wdt_fd;
static ipmi_timer_t *wdt_test_timer;
static volatile int wdt_test_timer_ran;

static void
add_to_timeval(struct timeval *tv, unsigned int usecs)
{
    while (usecs >= 1000000) {
	tv->tv_sec += 1;
	usecs -= 1000000;
    }
    tv->tv_usec += usecs;
    while (tv->tv_usec >= 1000000) {
	tv->tv_sec += 1;
	tv->tv_usec -= 1000000;
    }	
}

static void
diff_timeval(struct timeval *result, struct timeval *tv1, struct timeval *tv2)
{
    result->tv_sec = tv1->tv_sec - tv2->tv_sec;
    result->tv_usec = tv1->tv_usec - tv2->tv_usec;
    while (result->tv_usec < 0) {
	result->tv_usec += 1000000;
	result->tv_sec -= 1;
    }
}

static long
diff_timeval_ms(struct timeval *tv1, struct timeval *tv2)
{
    struct timeval tv;
    diff_timeval(&tv, tv1, tv2);

    if (tv.tv_sec > 1000)
	return 1000000;
    if (tv.tv_sec < -1000)
	return -1000000;
    return (tv.tv_sec * 1000) + ((tv.tv_usec + 500) / 1000);
}


/**************************************************************************
 * EEPROM handling
 *************************************************************************/

static unsigned char
checksum(unsigned char *data, int size)
{
	unsigned char csum = 0;
	
	for (; size > 0; size--, data++)
		csum += *data;

	return csum;
}

/*
 * Validate that the eeprom device exists and can be opened.
 */
static int
check_eeprom(sys_data_t *sys, const struct eeprom *e)
{
    int fd;

    fd = open(e->dev, O_RDONLY);
    if (fd == -1)
	return errno;
    close(fd);
    return 0;
}

/*
 * Write to the sysfs file to create the eeprom device.  Sometimes it
 * doesn't get automatically created, so create it here.
 */
static int
create_eeprom(sys_data_t *sys, const char *add_dev, const struct eeprom *e)
{
    int fd;

    fd = open(e->dev, O_RDONLY);
    if (fd == -1) {
	FILE *f;
	f = fopen(add_dev, "w");
	if (!f)
	    return errno;
	fprintf(f, "%s %d\n", e->part, e->addr);
	fclose(f);
	fd = open(e->dev, O_RDONLY);
	if (fd == -1)
	    return errno;
    }
    close(fd);
    return 0;
}

/* Note: Data must be at least e->size */
static int
read_eeprom(const struct eeprom *e, unsigned char *data,
	    unsigned int offset, int size)
{
    int rv;
    int err = 0;
    int fd;

    if (offset + size > e->size)
	return EINVAL;

    fd = open(e->dev, O_RDONLY);
    if (fd == -1)
	return errno;
    if (lseek(fd, offset, SEEK_SET) == -1) {
	err = errno;
	close(fd);
	return err;
    }
    rv = read(fd, data, size);
    if (rv == -1)
	err = errno;
    else if (rv < size)
	err = EIO;
    close(fd);
    return err;
}

/* Note: Data must be at least e->size */
static int
write_eeprom(const struct eeprom *e, unsigned char *data,
	     unsigned int offset, unsigned int size)
{
    int rv;
    int err = 0;
    int fd;

    if (size + offset > e->size)
	return EINVAL;

    fd = open(e->dev, O_WRONLY);
    if (fd == -1)
	return errno;
    if (lseek(fd, offset, SEEK_SET) == -1) {
	close(fd);
	return errno;
    }
    rv = write(fd, data, size);
    if (rv == -1)
	err = errno;
    else if (rv < size)
	err = EIO;
    close(fd);
    return err;
}


/**************************************************************************
 * General file handling.  These are functions that read and write
 * sysfs files, generally.
 *************************************************************************/

/*
 * Convert an integer value to a string and write it to the device.
 */
static int
set_intval(const char *fname, unsigned int val)
{
    FILE *f;

    f = fopen(fname, "w");
    if (!f)
	return errno;
    fprintf(f, "%u\n", val);
    fclose(f);
    return 0;
}

/*
 * Fetch an unsigned integer ASCII value from a file an convert it.
 */
static int
get_uintval(const char *fname, unsigned int *val)
{
    FILE *f;
    char line[80];
    int rv;

    f = fopen(fname, "r");
    if (!f)
       return errno;
    rv = fread(line, 1, sizeof(line), f);
    if (rv <= 0) {
	int retval = errno;
	fclose(f);
	return retval;
    }
    fclose(f);
    *val = strtoul(line, NULL, 0);
    return 0;
}

/*
 * Fetch a signed integer ASCII value from a file an convert it.
 */
static int
get_intval(const char *fname, int *val)
{
    FILE *f;
    char line[80];
    int rv;

    f = fopen(fname, "r");
    if (!f)
       return errno;
    rv = fread(line, 1, sizeof(line), f);
    if (rv == -1) {
	int retval = errno;
	fclose(f);
	return retval;
    }
    fclose(f);
    *val = strtol(line, NULL, 0);
    return 0;
}


/**************************************************************************
 * Board power handling.
 *
 * This is kept as a list of boards waiting to power on.  Only one
 * board may be waiting at a time, and the first thing in
 * boards_waiting_power_on will be the next thing to power on.
 *************************************************************************/

static ipmi_timer_t *power_timer;
static unsigned int boards_waiting_power_on[NUM_BOARDS];
static unsigned int num_boards_waiting_power_on;
static enum {
    PT_NOT_RUNNING,
    PT_RUNNING,
    PT_WAITING_RESET
} power_timer_running;

/*
 * Return true if the board is on, false if not.
 */
static int
board_power_state(sys_data_t *sys, unsigned int num)
{
    int rv;
    unsigned int rval;

    rv = get_uintval(trg_power[num], &rval);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to read board %u power state: %s",
		 num + 1, strerror(rv));
	return 0;
    }
    return rval == BOARD_POWER_ON;
}

/*
 * Return true if the given board number is waiting to power on.
 */
static int
board_waiting_power_on(unsigned int num)
{
    unsigned int i;

    for (i = 0; i < num_boards_waiting_power_on; i++) {
	if (boards_waiting_power_on[i] == num)
	    return 1;
    }
    return 0;
}

/*
 * Start the timer to power on the board.  The time will be
 * mintime + rand[1-6].
 */
static void
start_power_timer(sys_data_t *sys, unsigned int mintime)
{
    struct timeval tv;
    unsigned int to_add;

    sys->gen_rand(sys, &to_add, sizeof(to_add));
    to_add %= 5;
    to_add += 1 + mintime;
    tv.tv_sec = to_add;
    tv.tv_usec = 0;

    if (debug & 1)
	sys->log(sys, DEBUG, NULL, "Starting power timer on board %u for"
		 " %u seconds",
		 boards_waiting_power_on[0] + 1, to_add);
    sys->start_timer(power_timer, &tv);
    power_timer_running = PT_RUNNING;
}

/*
 * Set the given board number waiting to power up.
 */
static void
board_add_power_wait(sys_data_t *sys, unsigned int num)
{
    boards_waiting_power_on[num_boards_waiting_power_on] = num;
    num_boards_waiting_power_on++;
    if (num_boards_waiting_power_on == 1)
	start_power_timer(sys, 0);
}

/*
 * Remove the board from the power up wait list and start the next
 * board, if there is one.
 */
static void
board_remove_power_wait(sys_data_t *sys, unsigned int num)
{
    unsigned int i;

    for (i = 0; i < num_boards_waiting_power_on; i++) {
	if (boards_waiting_power_on[i] == num)
	    break;
    }
    if (i == num_boards_waiting_power_on)
	/* Not found */
	return;
    for (; i < num_boards_waiting_power_on - 1; i++)
	boards_waiting_power_on[i] = boards_waiting_power_on[i + 1];
    num_boards_waiting_power_on--;

    if (num_boards_waiting_power_on == 0) {
	sys->stop_timer(power_timer);
	if (!init_complete) {
	    set_intval(COLD_POWER_FILE, 0);
	    init_complete = 1;
	}
    } else if (power_timer_running == PT_NOT_RUNNING)
	start_power_timer(sys, 5);
}

static int
set_chassis_control(lmc_data_t *mc, int op, unsigned char *val, void *cb_data)
{
    struct board_info *board = cb_data;
    sys_data_t *sys = board->sys;
    unsigned int num = board->num;
    int wval;
    int rv, err;

    switch (op) {
    case CHASSIS_CONTROL_POWER:
	if (debug & 1) {
	    struct timeval now;
	    board->sys->get_real_time(board->sys, &now);
	    sys->log(sys, DEBUG, NULL, "Power request for board %d,"
		     " val=%d, wait=%d last=%ld.%ld, now=%ld.%ld",
		     board->num + 1, *val, board->waiting_power_off,
		     last_board_power_on.tv_sec, last_board_power_on.tv_sec,
		     now.tv_sec, now.tv_sec);
	}
	if (debug & 1 && board->waiting_power_off)
	    sys->log(sys, DEBUG, NULL, "Canceling power off wait on"
		     "board power request for board %d", board->num + 1);

	/* It's going to be forced on or off soon, just disable this. */
	board->waiting_power_off = 0;
	set_intval(pow_off_request[num], BOARD_OFF_REQUEST_OFF);

	if (*val) {
	    if (!board->present) {
		if (debug & 1)
		    sys->log(sys, DEBUG, NULL, "Power on request while board"
			     " not present on %d", num + 1);
		return EAGAIN;
	    }
	    if (!board_power_state(sys, num) && !board_waiting_power_on(num))
		board_add_power_wait(sys, num);
	    else if (debug & 1)
		sys->log(sys, DEBUG, NULL, "Power on request, but board was"
			 " alread on or waiting power up on board %d", num + 1);

	    /* We always delay for a power on. */
	    break;
	}

	/* We are powering off. */
	if (board_waiting_power_on(num)) {
	    /* Don't power on later. */
	    if (debug & 1)
		sys->log(sys, DEBUG, NULL, "Stopping board power timer"
			 " on %d", num + 1);
	    board_remove_power_wait(sys, num);
	}
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Setting board power off on %d",
		     num + 1);
	rv = set_intval(trg_power[num], BOARD_POWER_OFF);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL, "Warning: Unable to set power off"
		     " for board %d: %s", board->num, strerror(rv));
	    return rv;
	}

	/*
	 * We require a 0->1 transition for the power request to be
	 * honored, so start at 1 for the next time to avoid board
	 * insertion or startup issues.
	 */
	board->last_power_request = BOARD_OFF_READY;
	break;

    case CHASSIS_CONTROL_RESET:
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Resetting board %d", board->num + 1);
	set_intval(trg_reset[num], BOARD_RESET_ON);
	set_intval(trg_reset[num], BOARD_RESET_OFF);
	break;

    case CHASSIS_CONTROL_BOOT_INFO_ACK:
	/* Just ignore this for now */
	break;

    case CHASSIS_CONTROL_BOOT:
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Chassis control on %d present=%d, "
		     "fru_good=%d, val=%d", 
		     board->num + 1, boards[num].present,
		     boards[num].fru_good, *val);
	if (!boards[num].present)
	    return EAGAIN;
	if (!boards[num].fru_good)
	    return EBADFD;
	switch (*val) {
	case 0: /* none */
	    return 0;

	case 1: /* pxe */
	    wval = 1;
	    break;

	case 2: /* default */
	    wval = 0;
	    break;

	default:
	    return EINVAL;
	}

	rv = ipmi_mc_fru_sem_trywait(boards[num].mc, 0);
	if (rv)
	    return rv;

	boards[num].fru[11] = wval;
	rv = write_eeprom(&board_i2c[num].fru, boards[num].fru + 11, 11, 1);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL, "Warning: Error writing board %d"
		     " PXE boot: %s", num + 1, strerror(rv));
	} else {
	    boards[num].fru[79] = -checksum(boards[num].fru + 8, 71);
	    rv = write_eeprom(&board_i2c[num].fru, boards[num].fru + 79, 79, 1);
	    if (rv) {
		sys->log(sys, OS_ERROR, NULL, "Warning: Error writing"
			 " board %d"
			 " PXE boot checksum: %s", num + 1, strerror(rv));
		rv = 0;
	    }
	}
	err = ipmi_mc_fru_sem_post(board->mc, 0);
	if (err)
	    sys->log(sys, OS_ERROR, NULL,
		     "Error posting board %d semaphore: %s", num + 1,
		     strerror(err));
	return rv;

    case CHASSIS_CONTROL_GRACEFUL_SHUTDOWN:
	if (board_waiting_power_on(num)) {
	    if (debug & 1)
		sys->log(sys, DEBUG, NULL, "Graceful shutdown requested on %d,"
			 " shutting down power on timer", board->num + 1);
	    board_remove_power_wait(sys, num);
	} else if (board->waiting_power_off) {
	    /* Nothing to do, already waiting. */
	} else if (board_power_state(sys, num)) {
	    if (debug & 1)
		sys->log(sys, DEBUG, NULL, "Graceful shutdown requested on %d,"
			 " requesting board power off", board->num + 1);
	    board->waiting_power_off = 1;
	    board->power_off_countdown = 30;
	    set_intval(pow_off_request[num], BOARD_OFF_REQUEST_ON);
	}
	break;

    default:
	return EINVAL;
    }
    return 0;
}

static int
get_chassis_control(lmc_data_t *mc, int op, unsigned char *val, void *cb_data)
{
    struct board_info *board = cb_data;
    sys_data_t *sys = board->sys;
    unsigned int num = board->num;
    unsigned char cval;
    int rv, err;

    switch (op) {
    case CHASSIS_CONTROL_POWER:
	*val = (board_power_state(board->sys, num) ||
		board_waiting_power_on(num));
	break;

    case CHASSIS_CONTROL_BOOT_INFO_ACK:
	val[0] = 0;
	val[1] = 0;
	break;

    case CHASSIS_CONTROL_BOOT:
	rv = ipmi_mc_fru_sem_trywait(boards[num].mc, 0);
	if (rv)
	    return rv;
	rv = read_eeprom(&board_i2c[num].fru, &cval, 11, 1);
	if (rv)
	    goto out_post;
	switch(cval) {
	case 0:
	    *val = 2; /* default disk */
	    break;
	case 1:
	    *val = 1; /* pxe */
	    break;

	default:
	    *val = 0; /* Shouldn't happen */
	    break;
	}
    out_post:
	err = ipmi_mc_fru_sem_post(board->mc, 0);
	if (err)
	    sys->log(sys, OS_ERROR, NULL,
		     "Error posting board %d semaphore: %s", num + 1,
		     strerror(err));
	return rv;

    default:
	return EINVAL;
    }
    return 0;
}

/*
 * Chassis control for the chassis.  This will perform the operation on
 * all boards.
 */
static int
bmc_set_chassis_control(lmc_data_t *mc, int op, unsigned char *val,
			void *cb_data)
{
    sys_data_t *sys = cb_data;
    unsigned int i;

    switch (op) {
    case CHASSIS_CONTROL_POWER:
    case CHASSIS_CONTROL_RESET:
    case CHASSIS_CONTROL_BOOT_INFO_ACK:
    case CHASSIS_CONTROL_BOOT:
    case CHASSIS_CONTROL_GRACEFUL_SHUTDOWN:
	break;
    default:
	return EINVAL;
    }

    if (debug & 1) {
	struct timeval now;
	sys->get_real_time(sys, &now);
	sys->log(sys, DEBUG, NULL, "Power request for all boards,"
		 " val=%d, now=%ld.%ld",
		 *val, now.tv_sec, now.tv_sec);
    }

    for (i = 0; i < NUM_BOARDS; i++)
	set_chassis_control(NULL, op, val, &boards[i]);

    return 0;
}

/*
 * Chassis control get for the chassis.  This only works for the power
 * control, and will return on if any board in the chassis is on, and
 * off otherwise.
 */
static int
bmc_get_chassis_control(lmc_data_t *mc, int op, unsigned char *val,
			void *cb_data)
{
    unsigned int i;

    if (op == CHASSIS_CONTROL_POWER) {
	unsigned char rval = 0, tval;

	/* If any board is on, report power as on. */
	for (i = 0; i < NUM_BOARDS; i++) {
	    get_chassis_control(NULL, op, &tval, &boards[i]);
	    if (tval)
		rval = 1;
	}
	*val = rval;
	return 0;
    }

    /* This doesn't make sense for anything else. */
    return EINVAL;
}

static void
board_power_timeout(void *cb_data)
{
    sys_data_t *sys = cb_data;
    unsigned int num = boards_waiting_power_on[0];
    struct board_info *board = &boards[num];
    int rv;

    if (num_boards_waiting_power_on == 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: power timer went off"
		 " but no board waiting");
	return;
    }

    if (power_timer_running == PT_RUNNING) {
	struct timeval tv;

	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Powering on board %d", num + 1);

	/* Hold the reset on the board for 100ms while it powers on. */
	set_intval(trg_reset[num], BOARD_RESET_ON);

	rv = set_intval(trg_power[num], BOARD_POWER_ON);
	if (rv)
	    sys->log(sys, OS_ERROR, NULL, "Warning: Unable to set power on"
		     " for board %d: %s", num, strerror(rv));

	/* Start the 100ms reset timer */
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Starting reset timer on board %u",
		     num + 1);
	power_timer_running = PT_WAITING_RESET;
	tv.tv_sec = 0;
	tv.tv_usec = 100000;
	sys->start_timer(power_timer, &tv);
    } else {
	/* Take the board out of reset. */
	set_intval(trg_reset[num], BOARD_RESET_OFF);

	power_timer_running = PT_NOT_RUNNING;

	/* Starts the next one if something is waiting. */
	board_remove_power_wait(sys, num);
    }
}

static void
power_down_system(sys_data_t *sys)
{
    unsigned int i;
    unsigned char val = 0;

    for (i = 0; i < NUM_BOARDS; i++)
	set_chassis_control(NULL, CHASSIS_CONTROL_POWER, &val, &boards[i]);
}

/*
 * Called at init time to make sure the board state is sane.
 */
static void
check_chassis_state(sys_data_t *sys)
{
    unsigned int i;

    /* 
     * Make sure the reset is off on all boards.  The power state will
     * be set later.
     */
    for (i = 0; i < NUM_BOARDS; i++)
	set_intval(trg_reset[i], BOARD_RESET_OFF);
}

/**************************************************************************
 * Sensor handling
 *************************************************************************/

/*
 * The DIMM and CPU error sensors will remain set until rearmed.  This
 * is the rearm handling to clear those bits.
 */
struct eesense_rearm
{
    unsigned int num;
    unsigned int offset;
    unsigned char mask;
};

static int
rearm_eesense_sensor(void *cb_data,
		     uint16_t assert,
		     uint16_t deassert)
{
    struct eesense_rearm *info = cb_data;
    unsigned int num = info->num;
    unsigned int off = info->offset;
    unsigned char mask = info->mask;
    struct board_info *board = &boards[num];
    sys_data_t *sys = board->sys;
    unsigned char data[72];
    unsigned int i;
    int rv, err;

    if (!(assert & mask))
	return 0;

    rv = ipmi_mc_fru_sem_trywait(boards[num].mc, 0);
    if (rv)
	return rv;

    rv = read_eeprom(&board_i2c[num].fru, data, 8, 72);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Warning: Error reading board %d fru: %s",
		 num + 1, strerror(rv));
	goto out_post;
    }

    if (!(data[off] & mask))
	goto out_post;

    data[off] &= ~mask;
    data[71] = -checksum(data, 71);

    rv = write_eeprom(&board_i2c[num].fru, data + off, 8 + off, 1);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Warning: Error writing board %d"
		 " sensor data: %s", num + 1, strerror(rv));
	goto out_post;
    }

    for (i = 0; i < 8; i++)
	ipmi_mc_sensor_set_bit(boards[num].mc, 0, 19 + off, i,
			       ((data[off] >> i) & 1), 0);

    rv = write_eeprom(&board_i2c[num].fru, data + 71, 79, 1);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Warning: Error writing board %d"
		 " internal use checksum: %s", num + 1, strerror(rv));
	rv = 0;
    }

  out_post:
    err = ipmi_mc_fru_sem_post(board->mc, 0);
    if (err)
	sys->log(sys, OS_ERROR, NULL,
		 "Error posting board %d semaphore: %s", num + 1,
		 strerror(err));

    return rv;
}

/*
 * The rearm for the power supply sensor will set the clear fault flag
 * for the power supply, just to be sure it is clear.
 */
static int
rearm_power_supply_sensor(void *cb_data,
			  uint16_t assert,
			  uint16_t deassert)
{
    unsigned int num = (unsigned long) cb_data;
    sys_data_t *sys = boards[0].sys;
    int rv;
    char fname[100];

    if (!(assert & 2))
	return 0;

    sprintf(fname, "/sys/class/wixpmbus/CLEAR_FAULT_%d", num);
    rv = set_intval(fname, 1);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Error writing ps %d clear file: %s", num, strerror(rv));
	return rv;
    }
    return 0;
}


/**************************************************************************
 * Board handling
 *************************************************************************/

/*
 * Read the board's FRU and update anything that needs to be updated,
 * like the chassis information, the board's external MAC address, etc.
 */
static int
handle_board_fru(sys_data_t *sys, int num)
{
    int rv;
    unsigned int iuse;
    unsigned int iuse_len;
    unsigned int chinfo;
    unsigned int chinfo_len;
    unsigned int brdinfo;
    unsigned int brdinfo_len;
    unsigned int mac_offset;
    unsigned int brdchsernum_offset;
    unsigned int brdsernum_offset;
    int modified = 0;
    int fruversion2 = 0;
    unsigned char *fru;

    if (debug & 1)
	sys->log(sys, DEBUG, NULL, "Checking board FRU on board %d", num + 1);

    /* Guilty until proven innocent */
    boards[num].fru_good = 0;

    rv = read_eeprom(&board_i2c[num].fru, boards[num].fru,
		     0, board_i2c[num].fru.size);
    if (rv) {
	sys->log(sys, SETUP_ERROR, NULL, "Can't read board %d eeprom: %s",
		 num + 1, strerror(rv));
	return 0;
    }

    fru = boards[num].fru;

    if (fru[0] != 1) {
	sys->log(sys, SETUP_ERROR, NULL, "Invalid board %d FRU version: 0x%x",
		 num + 1, fru[0]);
	return 0;
    }

    if (checksum(fru + 0, 8) != 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Board %d FRU header"
		 " checksum fail", num + 1);
    }

    iuse = fru[1] * 8;
    iuse_len = 80 - 8;
    chinfo = fru[2] * 8;
    chinfo_len = 256 - 80;
    brdinfo = fru[3] * 8;
    brdinfo_len = 2048 - 256;
    brdchsernum_offset = 42;
    brdsernum_offset = 74;
    mac_offset = 95;

    if (iuse != 8) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Board %d FRU internal use"
		 "area is not at offset 8", num + 1);
	return 0;
    }
    if (chinfo != 80) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Board %d FRU chassis info"
		 "area is not at offset 80", num + 1);
	return 0;
    }
    if (brdinfo != 256) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Board %d FRU board info"
		 "area is not at offset 256", num + 1);
	return 0;
    }
    if (checksum(fru + iuse, iuse_len) != 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Board %d FRU internal use"
		 " checksum fail", num + 1);
	return 0;
    }
    if (checksum(fru + chinfo, chinfo_len) != 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Board %d FRU chassis info"
		 " checksum fail", num + 1);
	return 0;
    }
    if (checksum(fru + brdinfo, brdinfo_len) != 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Board %d FRU board info"
		 " checksum fail", num + 1);
	return 0;
    }
    boards[num].fru_good = 1;

    /* Set the chassis information if it is not correct. */
    if (chassis_fru[chinfo + brdchsernum_offset] != 0xd4) {
	/* Try the version 2.0 of the FRU data */
	brdchsernum_offset = 17;
    }
    if (sernum_len == 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: FRU chassis serial number"
		 " invalid, not setting board %d data", num + 1);
    } else if (chassis_chinfo == 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Chassis chassis info FRU"
		 "invalid, not checking board %d FRU chassis data", num + 1);
    } else {
	/*
	 * If we have a different FRU version, or if the serial
	 * numbers don't match, then update the chassis info area.
	 */
	if ((brdchsernum_offset != sernum_offset) ||
	    memcmp(fru + chinfo + brdchsernum_offset,
		   chassis_fru + chassis_chinfo + sernum_offset,
		   sernum_len) != 0) {
	    /* The chassis serial number has changed. */
	    sys->log(sys, INFO, NULL, "Info: Updating board %d"
		     " chassis info area", num + 1);
	    memcpy(fru + chinfo, chassis_fru + chassis_chinfo,
		   chassis_chinfo_len);
	    rv = write_eeprom(&board_i2c[num].fru, fru + chinfo, chinfo,
			      chassis_chinfo_len);
	    if (rv) {
		sys->log(sys, OS_ERROR, NULL,
			 "Warning: Error writing board %d"
			 " chassis info: %s", num + 1, strerror(rv));
	    }
	}
    }

    /* Set the board system serial number if it is not correct. */
    if (fru[brdinfo + brdsernum_offset] != 0xd4) {
	/* FRU version 2.0 */
	brdsernum_offset = 34;
	fruversion2 = 1;
    }
    if (fru[brdinfo + brdsernum_offset] != 0xd4) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Board %d FRU serial num"
		 " data invalid", num + 1);
    } else if (!sernum[0]) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: System serial num invalid,"
		 " not checking board %d ser num", num + 1);
    } else {
	char mysernum[21];

	if (fruversion2) {
	    int len;
	    len = sprintf(mysernum, "%s-%c", sernum, num + 'A');
	    memset(mysernum + len, ' ', 20 - len);
	    mysernum[20] = '\0';
	} else {
	    memset(mysernum, 0, 21);
	    sprintf(mysernum, "System SN %s-%c", sernum, num + 'A');
	}
	
	if (memcmp(mysernum, fru + brdinfo + brdsernum_offset + 1, 20) != 0) {
	    sys->log(sys, INFO, NULL, "Info: Updating board %d"
		     " serial number", num + 1);
	    memcpy(fru + brdinfo + brdsernum_offset + 1, mysernum, 20);
	    rv = write_eeprom(&board_i2c[num].fru, 
			      fru + brdinfo + brdsernum_offset + 1,
			      brdinfo + brdsernum_offset + 1,
			      20);
	    if (rv) {
		sys->log(sys, OS_ERROR, NULL,
			 "Warning: Error writing board %d"
			 " serial num: %s", num + 1, strerror(rv));
	    }
	    modified = 1;
	}
    }

    /* Set the board MAC address if it is not correct. */
    if (fru[brdinfo + mac_offset] != 0xdc) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Board %d FRU external MAC"
		 " data invalid", num + 1);
    } else if (!sysmac[0]) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: System MAC invalid, not"
		 " checking board %d MAC", num + 1);
    } else {
	char mac[29];

	memset(mac, 0, 29);
	sprintf(mac, "System MAC %s%d", sysmac, num + 1);
	if (memcmp(mac, fru + brdinfo + mac_offset + 1, 28) != 0) {
	    sys->log(sys, INFO, NULL, "Info: Updating board %d"
		     " MAC address", num + 1);
	    memcpy(fru + brdinfo + mac_offset + 1, mac, 28);
	    rv = write_eeprom(&board_i2c[num].fru, 
			      fru + brdinfo + mac_offset + 1,
			      brdinfo + mac_offset + 1,
			      28);
	    if (rv) {
		sys->log(sys, OS_ERROR, NULL,
			 "Warning: Error writing board %d"
			 " MAC address: %s", num + 1, strerror(rv));
	    }
	    modified = 1;
	}
    }

    if (modified) {
	/* Recalculate the board checksum */
	fru[brdinfo + brdinfo_len - 1] = -checksum(fru + brdinfo,
						   brdinfo_len - 1);

	rv = write_eeprom(&board_i2c[num].fru, fru + brdinfo + brdinfo_len - 1,
			  brdinfo + brdinfo_len - 1, 1);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL, "Warning: Error writing board %d"
		     " board info checksum: %s", num + 1, strerror(rv));
	}
    }
    return 0;
}

/*
 * Check that the board has not changed states, and if it has then
 * handle the change.  Called on insertion/removal events and
 * periodically by a timer.
 */
static int
check_board(sys_data_t *sys, int num, unsigned int since_last,
	    int power_up_new_board)
{
    int rv;
    unsigned int present;
    unsigned int rval;
    unsigned char val;
    struct board_info *board = &boards[num];

    if (board->present && board_power_state(sys, num)) {
	rv = get_uintval(pow_off_ready[num], &rval);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "Unable to read board %u power off ready: %s",
		     num, strerror(rv));
	} else {
	    if (board->last_power_request == BOARD_OFF_NOT_READY &&
		rval == BOARD_OFF_READY) {
		if (debug & 1) {
		    if (board->waiting_power_off)
			sys->log(sys, DEBUG, NULL, "Graceful power of finished"
				 " on %d, setting power off", board->num + 1);
		    else
			sys->log(sys, DEBUG, NULL, "Board %d requested power"
				 " off, setting power off", board->num + 1);
		}
		val = 0;
		set_chassis_control(NULL, CHASSIS_CONTROL_POWER, &val, board);
	    }
	    board->last_power_request = rval;
	}
    }

    if (board->waiting_power_off && since_last) {
	if (board->power_off_countdown == 0) {
	    unsigned char val;

	    if (debug & 1)
		    sys->log(sys, DEBUG, NULL, "Graceful power off timeout"
			     " on %d, forcing power off", board->num + 1);
	    val = 0;
	    set_chassis_control(NULL, CHASSIS_CONTROL_POWER, &val, board);
	} else {
	    board->power_off_countdown--;
	}
    }

    rv = get_uintval(trg_present[num], &present);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL, "Unable to read board %d presence: %s",
		 num + 1, strerror(rv));
	return rv;
    }
    present = (present == BOARD_PRESENT) && !simulate_board_absent[num];
    if (board->present == present)
	return 0;

    board->present = present;
    if (!present) {
	sys->log(sys, INFO, NULL, "Info: board %d has been removed", num + 1);

	board->fru_good = 0;

	/*
	 * Turn off board power when not present, that way we can hold
	 * off power on until we are done with messing with the board FRU
	 * data.
	 */
	val = 0;
	set_chassis_control(NULL, CHASSIS_CONTROL_POWER, &val, board);
	return 0;
    }

    sys->log(sys, INFO, NULL, "Info: board %d is now present", num + 1);

    rv = create_eeprom(sys, board_i2c[num].add_dev, &board_i2c[num].fru);
    if (rv) {
	/* Force a retry, perhaps the device hasn't been created yet */
	board->present = 0;
	sys->log(sys, SETUP_ERROR, NULL, "Can't create board %d eeprom: %s."
		 "  Will retry in a second",
		 num + 1, strerror(rv));
	return 0;
    }

    rv = handle_board_fru(sys, num);
    if (rv)
	return rv;

    if (power_up_new_board) {
	/* If the board was not present and now it is, power it on. */
	val = 1;
	set_chassis_control(NULL, CHASSIS_CONTROL_POWER, &val, board);
    }

    return 0;
}

/*
 * If the board front-panel button is pressed, record the time, the
 * button will be handled on release.
 */
static void
handle_button_press(sys_data_t *sys, unsigned int brdnum)
{
    struct board_info *board = &boards[brdnum];

    if (debug & 1)
	sys->log(sys, DEBUG, NULL, "Button press on %d", board->num + 1);

    board->button_pressed = 1;
    board->sys->get_monotonic_time(board->sys, &board->button_press_time);
}

/*
 * Handle the board's front-panel button.
 */
static void
handle_button_release(sys_data_t *sys, unsigned int num)
{
    struct timeval now;
    unsigned char val;
    struct board_info *board = &boards[num];
    int power_state = board_power_state(sys, num);

    if (!board->button_pressed)
	return;

    if (debug & 1)
	sys->log(sys, DEBUG, NULL, "Button release on %d", num + 1);

    board->button_pressed = 0;

    board->sys->get_monotonic_time(board->sys, &now);

    /*
     * If the button is pressed more than 4 seconds, start a graceful
     * shutdown.
     */ 
    if (power_state &&
        (diff_timeval_ms(&now, &board->button_press_time) > 4000)) {
	if (board_waiting_power_on(num)) {
	    if (debug & 1)
		sys->log(sys, DEBUG, NULL, "Button press on %d >4sec, stop"
			 " power on timer", board->num + 1);
	    board_remove_power_wait(sys, num);
	} else {
	    if (debug & 1)
		sys->log(sys, DEBUG, NULL, "Button press on %d >4sec, start"
			 " graceful shutdown", board->num + 1);
	    val = 0;
	    set_chassis_control(NULL, CHASSIS_CONTROL_GRACEFUL_SHUTDOWN,
			        &val, board);
	}
    }

    /*
     * If the button is pressed less than 4 seconds, start a power up
     * if the board is not already on.
     */ 
    if (!power_state &&
        (diff_timeval_ms(&now, &board->button_press_time) <= 4000)) {
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Button press on %d <4sec, power on",
		board->num + 1);

	val = 1;
	set_chassis_control(NULL, CHASSIS_CONTROL_POWER, &val, board);
    }
}

/*
 * Read data from the chassis FRU.
 */
static int
init_chassis(sys_data_t *sys)
{
    int rv;

    if (debug & 1)
	sys->log(sys, DEBUG, NULL, "Reading chassis eeprom info");

    /* Detect which I2C channel to use for the chassis I2C. */
    rv = check_eeprom(sys, &chassis_i2c_new.fru);
    if (rv) {
	rv = check_eeprom(sys, &chassis_i2c_old.fru);
	if (rv) {
	    sys->log(sys, SETUP_ERROR, NULL, "Can't find chassis eeprom: %s",
		     strerror(rv));
	    return rv;
	}
	chassis_i2c = &chassis_i2c_old;
    } else {
	chassis_i2c = &chassis_i2c_new;
    }

    rv = read_eeprom(&chassis_i2c->fru, chassis_fru, 0, chassis_i2c->fru.size);
    if (rv) {
	sys->log(sys, SETUP_ERROR, NULL, "Can't read chassis eeprom: %s",
		 strerror(rv));
	return rv;
    }

    if (chassis_fru[0] != 1) {
	sys->log(sys, SETUP_ERROR, NULL, "Invalid Chassis FRU version: 0x%x",
		 chassis_fru[0]);
	return EINVAL;
    }

    if (checksum(chassis_fru + 0, 8) != 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Chassis FRU header"
		 " checksum fail");
    }

    chassis_iuse = chassis_fru[1] * 8;
    chassis_iuse_len = 80 - 8;
    chassis_chinfo = chassis_fru[2] * 8;
    chassis_chinfo_len = 256 - 80;
    chassis_brdinfo = chassis_fru[3] * 8;
    chassis_brdinfo_len = 1024 - 256;
    sernum_offset = 42;
    sernum_offset2 = 11;
    sernum_len = 20;
    sysmac_offset = 74;

    if (chassis_iuse != 8) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Chassis FRU internal use"
		 "area is not at offset 8");
    }
    if (chassis_chinfo != 80) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Chassis FRU chassis info"
		 "area is not at offset 80");
    }
    if (chassis_brdinfo != 256) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Chassis FRU board info"
		 "area is not at offset 256");
    }
    if (checksum(chassis_fru + chassis_iuse, chassis_iuse_len) != 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Chassis FRU internal use"
		 " checksum fail");
    }
    if (checksum(chassis_fru + chassis_chinfo, chassis_chinfo_len) != 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Chassis FRU chassis info"
		 " checksum fail");
    }
    if (checksum(chassis_fru + chassis_brdinfo, chassis_brdinfo_len) != 0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Chassis FRU board info"
		 " checksum fail");
    }

    if (chassis_fru[chassis_chinfo + sernum_offset] != 0xd4) {
	/* Try the version 2.0 of the FRU data */
	sernum_offset = 17;
	sernum_offset2 = 1;
    }
    if (chassis_fru[chassis_chinfo + sernum_offset] != 0xd4) {
	sys->log(sys, SETUP_ERROR, NULL,
		 "Warning: Chassis FRU system serial"
		 " number data invalid");
	sernum_len = 0;
    } else {
	memcpy(sernum, chassis_fru + chassis_chinfo + sernum_offset
	       + sernum_offset2, 8);
	sernum[9] = '\0';
    }

    if (chassis_fru[chassis_brdinfo + sysmac_offset] != 0xe0) {
	sys->log(sys, SETUP_ERROR, NULL, "Warning: Chassis FRU system MAC"
		 " data invalid");
    } else {
	/* Don't copy the last byte, we use that for the boards. */
	memcpy(sysmac, chassis_fru + chassis_brdinfo + sysmac_offset + 14, 16);
	sysmac[16] = '\0';
    }
	
    return 0;
}

/**************************************************************************
 * Event/timer handling
 *************************************************************************/

static int ast_fd;
static ipmi_io_t *ast_fd_id;
static int fork_event_wait = 0;

static void
ast_evt(int fd, void *cb_data)
{
    int rv;
    int event;
    sys_data_t *sys = cb_data;

    if (!fork_event_wait) {
	rv = ioctl(fd, READ_WIW_NONBLOCKING, &event);
	if (rv == -1) {
	    sys->log(sys, OS_ERROR, NULL, "Warning: MV: Error reading"
		     " AST event: %s", strerror(errno));
	    return;
	}
    } else {
	unsigned char c;
	rv = read(fd, &c, 1);
	if (rv != 1) {
	    sys->log(sys, OS_ERROR, NULL, "Warning: MV: AST1300 shim"
		     " failed: %s", strerror(errno));
	    exit(1);
	}
	event = c;
    }

    if (debug & 1)
	sys->log(sys, DEBUG, NULL, "Got event %d", event);

    switch (event) {
    case WIW_NO_EVENT:
	break;

    case WIW_NODE1_IN:
    case WIW_NODE1_OUT:
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Board %s on 1",
		     event == WIW_NODE1_IN ? "insertion" : "removal");
	check_board(sys, 0, 0, 1);
	break;

    case WIW_NODE2_IN:
    case WIW_NODE2_OUT:
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Board %s on 2",
		     event == WIW_NODE2_IN ? "insertion" : "removal");
	check_board(sys, 1, 0, 1);
	break;

    case WIW_NODE3_IN:
    case WIW_NODE3_OUT:
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Board %s on 3",
		     event == WIW_NODE3_IN ? "insertion" : "removal");
	check_board(sys, 2, 0, 1);
	break;

    case WIW_NODE4_IN:
    case WIW_NODE4_OUT:
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Board %s on 4",
		     event == WIW_NODE4_IN ? "insertion" : "removal");
	check_board(sys, 3, 0, 1);
	break;

    case WIW_NODE5_IN:
    case WIW_NODE5_OUT:
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Board %s on 5",
		     event == WIW_NODE5_IN ? "insertion" : "removal");
	check_board(sys, 4, 0, 1);
	break;

    case WIW_NODE6_IN:
    case WIW_NODE6_OUT:
	if (debug & 1)
	    sys->log(sys, DEBUG, NULL, "Board %s on 6",
		     event == WIW_NODE6_IN ? "insertion" : "removal");
	check_board(sys, 5, 0, 1);
	break;

    case WIW_NODE1_PBTN_P:
	handle_button_press(sys, 0);
	break;

    case WIW_NODE1_PBTN_R:
	handle_button_release(sys, 0);
	break;

    case WIW_NODE2_PBTN_P:
	handle_button_press(sys, 1);
	break;

    case WIW_NODE2_PBTN_R:
	handle_button_release(sys, 1);
	break;

    case WIW_NODE3_PBTN_P:
	handle_button_press(sys, 2);
	break;

    case WIW_NODE3_PBTN_R:
	handle_button_release(sys, 2);
	break;

    case WIW_NODE4_PBTN_P:
	handle_button_press(sys, 3);
	break;

    case WIW_NODE4_PBTN_R:
	handle_button_release(sys, 3);
	break;

    case WIW_NODE5_PBTN_P:
	handle_button_press(sys, 4);
	break;

    case WIW_NODE5_PBTN_R:
	handle_button_release(sys, 4);
	break;

    case WIW_NODE6_PBTN_P:
	handle_button_press(sys, 5);
	break;

    case WIW_NODE6_PBTN_R:
	handle_button_release(sys, 5);
	break;

    default:
	break;
    }
}


/*
 * This timer is called periodically to check the boards.
 */
static ipmi_timer_t *mv_timer;

static void
mv_timeout(void *cb_data)
{
    int i;
    struct timeval tv;
    sys_data_t *sys = cb_data;

    for (i = 0; i < NUM_BOARDS; i++)
	check_board(sys, i, 1, 1);

    tv.tv_sec = 1;
    tv.tv_usec = 0;
    sys->start_timer(mv_timer, &tv);
}

static void
shim_sig(int signr)
{
    exit(1);
}

/*
 * The ast1300 device doesn't support select() in older
 * implementations.  So add a small program that will wait for it
 * blocking and then feed it to the program through a pipe, which will
 * work as a select() device.
 */
static void
ast1300_shim(sys_data_t *sys, int ast_fd, int writefd, int pid)
{
    unsigned char c;
    int rv;
    int event;
    struct sigaction act;

    /*
     * Make sure to terminate if the main program goes away.
     */
    memset(&act, 0, sizeof(act));
    act.sa_handler = shim_sig;
    rv = sigaction(SIGCHLD, &act, NULL);
    if (rv == -1) {
	sys->log(sys, OS_ERROR, NULL, "Warning: MV: Error settint up"
		 " signal: %s", strerror(errno));
	exit(1);
    }

    for (;;) {
	rv = ioctl(ast_fd, READ_WIW_BLOCKING, &event);
	if (rv == -1) {
	    sys->log(sys, OS_ERROR, NULL, "Warning: MV: Error reading"
		     " AST event: %s", strerror(errno));
	    exit(1);
	}
	c = event;
	rv = write(writefd, &c, 1);
	if (rv != 1) {
	    /* Other end of the pipe went away, just shut down. */
	    exit(0);
	}
    }
}

/**************************************************************************
 * General sensor handling
 *************************************************************************/

struct sensor_info {
    char *filename;
    unsigned char sensor_number;
    char *create_file;
    char *create_data;
    int invalid_if_off;
    int mult;
    int div;
    int sub;
};
static struct sensor_info empty_sensors[] = { { NULL } };

static int all_fans_duty = 0;

struct fan_duty_table {
    int reading;
    int setting;
};

struct sensor_handling {
    struct sensor_info *switch_s;
    char *switch_valids;
    int *switch_last_values;
    struct sensor_info *board;
    char (*board_valids)[NUM_BOARDS];
    int (*board_last_values)[NUM_BOARDS];
    struct fan_duty_table *fan_duty;

    /* Modify the duty tables by this much. */
    int duty_offset;
};

static struct sensor_info switch_temp_sensors[] =
{
    /* Switch Temp */
    { "/sys/class/i2c-adapter/i2c-0/0-0058/temp2_input", 1, .div = 1000 },
    /* Switch CPU Temp */
    { "/sys/class/i2c-adapter/i2c-0/0-0058/temp3_input", 2, .div = 1000 },
    { NULL }
};
static char switch_temp_sensor_valids[2];
static int switch_temp_sensor_last_values[2];
static struct sensor_info board_temp_sensors[] =
{
    /* Board CPU Temp */
    { "/sys/class/i2c-adapter/i2c-%d/%d-0064/temp1_input", 2, .div = 1000,
      .invalid_if_off = 1,
      .create_file = "/sys/class/i2c-adapter/i2c-%d/new_device",
      .create_data = "axp 0x64" },
    /* Board DIMM Temp */
    { "/sys/class/i2c-adapter/i2c-%d/%d-001e/temp1_input", 3, .div = 1000,
      .invalid_if_off = 1,
      .create_file = "/sys/class/i2c-adapter/i2c-%d/new_device",
      .create_data = "dimm 0x1e" },
    { NULL }
};
static char board_temp_sensor_last_oor[NUM_BOARDS];
static char board_temp_sensor_valids[2][NUM_BOARDS];
static int board_temp_sensor_last_values[2][NUM_BOARDS];
static struct fan_duty_table main_fan_duty_table[] =
{
    { 0,  42 },
    { 60,  45 },
    { 65,  48 },
    { 70,  51 },
    { 75,  54 },
    { 80,  57 },
    { 85,  60 },
    { 95,  70 },
    { 100, 85 },
    { 105, 100 },
    { -1 }
};
static struct sensor_handling main_temp =
{
    .switch_s = switch_temp_sensors,
    .switch_valids = switch_temp_sensor_valids,
    .switch_last_values = switch_temp_sensor_last_values,
    .board = board_temp_sensors,
    .board_valids = board_temp_sensor_valids,
    .board_last_values = board_temp_sensor_last_values,
    .fan_duty = main_fan_duty_table,
    .duty_offset = 10
};

static struct sensor_info board_mb_sensors[] =
{
    /* Board MB Temp */
    { "/sys/class/i2c-adapter/i2c-%d/%d-004a/temp1_input", 1, .div = 1000 },
    { NULL }
};
static char board_mb_sensor_valids[1][NUM_BOARDS];
static int board_mb_sensor_last_values[1][NUM_BOARDS];
static struct fan_duty_table mb_fan_duty_table[] =
{
    {  0, 42 },
    { 50, 45 },
    { 52, 48 },
    { 54, 51 },
    { 56, 54 },
    { 58, 57 },
    { 60, 60 },
    {  -1 }
};
static struct sensor_handling mb_temp =
{
    .switch_s = empty_sensors,
    .board = board_mb_sensors,
    .board_valids = board_mb_sensor_valids,
    .board_last_values = board_mb_sensor_last_values,
    .fan_duty = mb_fan_duty_table,
    .duty_offset = 0
};

static struct sensor_info board_front_sensors[] =
{
    /* Board Front Temp */
    { "/sys/class/i2c-adapter/i2c-%d/%d-004c/temp1_input", 4, .div = 1000 },
    { NULL }
};
static char board_front_sensor_valids[1][NUM_BOARDS];
static int board_front_sensor_last_values[1][NUM_BOARDS];
static struct fan_duty_table front_fan_duty_table[] =
{
    {  0, 42 },
    { 37, 65 },
    { 39, 70 },
    { 41, 75 },
    { 43, 80 },
    { 45, 85 },
    {  -1 }
};
static struct sensor_handling front_temp =
{
    .switch_s = empty_sensors,
    .board = board_front_sensors,
    .board_valids = board_front_sensor_valids,
    .board_last_values = board_front_sensor_last_values,
    .fan_duty = front_fan_duty_table,
    .duty_offset = 0
};

static struct sensor_info switch_sensors[] =
{
    /* Switch 12v  */
    { "/sys/class/i2c-adapter/i2c-0/0-0058/in11_input", 3,
      .mult=8, .div=125, .sub=10000 },
    /* Switch 3.3v  */
    { "/sys/class/i2c-adapter/i2c-0/0-0058/in10_input", 4,
      .mult=8, .div=25, .sub=2900 },
    /* Switch 1.8v  */
    { "/sys/class/i2c-adapter/i2c-0/0-0058/in2_input", 5,
      .mult=16, .div=25, .sub=1600 },
    /* Fans */
    { "/sys/class/astfan/fan1_input", 0x70, .mult = 10, .div = 392 },
    { "/sys/class/astfan/fan2_input", 0x71, .mult = 10, .div = 392 },
    { "/sys/class/astfan/fan3_input", 0x72, .mult = 10, .div = 392 },
    { "/sys/class/astfan/fan4_input", 0x73, .mult = 10, .div = 392 },
    { "/sys/class/astfan/fan5_input", 0x74, .mult = 10, .div = 392 },
    { "/sys/class/astfan/fan6_input", 0x75, .mult = 10, .div = 392 },
    { "/sys/class/astfan/fan7_input", 0x76, .mult = 10, .div = 392 },
    { "/sys/class/astfan/fan8_input", 0x77, .mult = 10, .div = 392 },
    { NULL }
};
static char switch_sensor_valids[11];
static int switch_sensor_last_values[11];
static struct sensor_info board_sensors[] =
{
    /* Board 1.0v */
    { "/sys/class/i2c-adapter/i2c-%d/%d-0048/in3_input", 5,
      .mult=32, .div=25, .sub=900,
      .invalid_if_off = 1 },
    /* Board 1.8v */
    { "/sys/class/i2c-adapter/i2c-%d/%d-0048/in2_input", 6,
      .mult=16, .div=25, .sub=1600,
      .invalid_if_off = 1 },
    /* Board 2.5v */
    { "/sys/class/i2c-adapter/i2c-%d/%d-0048/in1_input", 7,
      .mult=32, .div=125, .sub=2000,
      .invalid_if_off = 1 },
    /* Board 3.3v */
    { "/sys/class/i2c-adapter/i2c-%d/%d-0048/in0_input", 8, 
      .mult=8, .div=25, .sub=2900,
      .invalid_if_off = 1 },
    /* Board 1.05v */
    { "/sys/class/i2c-adapter/i2c-%d/%d-0049/in2_input", 9,
      .mult=16, .div=25, .sub=800,
      .invalid_if_off = 1 },
    /* Board DIMMv */
    { "/sys/class/i2c-adapter/i2c-%d/%d-0049/in1_input", 11,
      .mult=64, .div=75, .sub=1200,
      .invalid_if_off = 1 },
    /* Board 0.9v */
    { "/sys/class/i2c-adapter/i2c-%d/%d-0049/in0_input", 12,
      .mult=21, .div=50, .sub=700,
      .invalid_if_off = 1 },
    { NULL }
};
static char board_sensor_valids[8][NUM_BOARDS];
static int board_sensor_last_values[8][NUM_BOARDS];
static struct sensor_handling system_sensors =
{
    .switch_s = switch_sensors,
    .switch_valids = switch_sensor_valids,
    .switch_last_values = switch_sensor_last_values,
    .board = board_sensors,
    .board_valids = board_sensor_valids,
    .board_last_values = board_sensor_last_values,
};


static int
get_readings(sys_data_t *sys, struct sensor_handling *h, int *rmax)
{
    int err;
    int success = 0;
    int max = 0;
    unsigned int i, j;

    for (i = 0; h->switch_s[i].filename; i++) {
	int value;

	err = get_intval(h->switch_s[i].filename, &value);
	if (debug & 2)
	    sys->log(sys, DEBUG, NULL, "Read value %s: %d %d",
		     h->switch_s[i].filename, err, value);
	if (err) {
	    h->switch_valids[i] = 0;
	} else {
	    success = 1;
	    h->switch_valids[i] = 1;
	    h->switch_last_values[i] = value;
	    if (value > max)
		max = value;
	}
    }

    for (i = 0; h->board[i].filename; i++) {
	for (j = 0; j < NUM_BOARDS; j++) {
	    int value;
	    char filename[100];

	    if (!boards[j].present ||
		(h->board[i].invalid_if_off && !board_power_state(sys, j))) {
		h->board_valids[i][j] = 0;
		continue;
	    }

	    sprintf(filename, h->board[i].filename, j + 1, j + 1);

	    err = get_intval(filename, &value);
	    if ( err && h->board[i].create_file) {
		/* The sysfs file doesn't exist, create it. */
		char cfilename[100];
		FILE *f;

		sprintf(cfilename, h->board[i].create_file, j + 1);
		f = fopen(cfilename, "w");
		if (!f) {
		    sys->log(sys, OS_ERROR, NULL, "Unable to create %s",
			     filename);
		} else {
		    fprintf(f, "%s\n", h->board[i].create_data);
		    fclose(f);
		}
		err = get_intval(filename, &value);
	    }

	    if (debug & 2)
		sys->log(sys, DEBUG, NULL, "Read value %s: %d %d",
			 filename, err, value);
	    if (err) {
		sys->log(sys, OS_ERROR, NULL, "Sensor read error of %s: %s",
			 filename, strerror(err));
		h->board_valids[i][j] = 0;
	    } else {
		success = 1;
		h->board_valids[i][j] = 1;
		h->board_last_values[i][j] = value;
		if (value > max)
		    max = value;
	    }
	}
    }

    if (rmax)
	*rmax = max;
    return !success;
}

static int
calc_duty(struct fan_duty_table *t, int duty_offset,
	  int v, int *last_v, int *last_duty)
{
    unsigned int i;
    int duty = 0;

    /* Hysteresis when going down, and is two degress C. */
    if (v < *last_v)
	v += 2000;

    /* Convert to degrees, rounding */
    v = (v + 500) / 1000;

    for (i = 1; t[i].reading != -1; i++) {
	if (v < t[i].reading)
	    break;
    }
    duty = t[i - 1].setting + duty_offset;
    if (duty > 100)
	duty = 100;
    if (duty < 42)
	duty = 42;
    if (duty != *last_duty) {
	*last_duty = duty;
	*last_v = v;
    } else if (v > *last_v) {
	/*
	 * This is subtle, but is required to correctly implement
	 * hysteresis.  We don't want to get in a situation where the
	 * temperature goes down, but is still in the hysteresis area,
	 * then goes back up a little bit.  So we only set last_v when
	 * going up.
	 */
	*last_v = v;
    }

    return duty;
}

static int last_main_v, last_mb_v, last_front_v;
static int last_main_duty, last_mb_duty, last_front_duty;
static int last_duty;

static int scan_pipe[2];
static pthread_mutex_t scan_mutex = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t scan_cond = PTHREAD_COND_INITIALIZER;
static pthread_t scan_thread;
static ipmi_io_t *scan_fd_id;

static int eesense_data_ready[NUM_BOARDS];
static unsigned char cpu_errors[NUM_BOARDS];
static uint16_t dimm_errors[NUM_BOARDS];

static int ps_status_good[2];
static unsigned int ps_status_word[2];

static void
scan_eeprom_sensors(sys_data_t *sys)
{
    int rv;
    unsigned int i;

    for (i = 0; i < NUM_BOARDS; i++) {
	if (!boards[i].present) {
	    eesense_data_ready[i] = 0;
	} else {
	    unsigned char data[2];

	    rv = ipmi_mc_fru_sem_trywait(boards[i].mc, 0);
	    if (rv)
		continue;

	    rv = read_eeprom(&board_i2c[i].fru, data, 9, 2);
	    if (rv) {
		eesense_data_ready[i] = 0;
		sys->log(sys, OS_ERROR, NULL,
			 "Error reading eeprom sensors for %d: %s",
			 i + 1, strerror(rv));
	    } else {
		eesense_data_ready[i] = 1;
		cpu_errors[i] = data[0];
		dimm_errors[i] = data[1];
	    }
	    rv = ipmi_mc_fru_sem_post(boards[i].mc, 0);
	    if (rv)
		sys->log(sys, OS_ERROR, NULL,
			 "Error posting board %d semaphore: %s", i + 1,
			 strerror(rv));
	}
    }
}

static void
scan_ps_sensors(sys_data_t *sys)
{
    int rv;
    unsigned int i;

    rv = get_uintval("/sys/class/wixpmbus/STATUS_1", &i);
    if (rv) {
	/* Not present */
	ps_status_good[0] = 0;
    } else {
	ps_status_good[0] = 1;
	ps_status_word[0] = i;
    }
    rv = get_uintval("/sys/class/wixpmbus/STATUS_2", &i);
    if (rv) {
	/* Not present */
	ps_status_good[1] = 0;
    } else {
	ps_status_good[1] = 1;
	ps_status_word[1] = i;
    }
}

static char *fan_fail_led[4]  =
{
    "/sys/class/astgpio/GPIOP0",
    "/sys/class/astgpio/GPIOP1",
    "/sys/class/astgpio/GPIOP2",
    "/sys/class/astgpio/GPIOP3",
};

static void *
scan_sensors(void *cb_data)
{
    sys_data_t *sys = cb_data;
    int err;
    int duty;
    int max_temp = 0;
    int max_duty = 0;
    char dummy = 0;
    struct timeval next, now, wait;
    unsigned int i;
    char fan_fail[8];
	    
    for (;;) {
	sys->get_monotonic_time(sys, &next);
	add_to_timeval(&next, poll_time);

	err = get_readings(sys, &main_temp, &max_temp);
	if (!err) {
	    max_duty = calc_duty(main_temp.fan_duty, main_temp.duty_offset,
				 max_temp, &last_main_v, &last_main_duty);
	}
	err = get_readings(sys, &mb_temp, &max_temp);
	if (!err) {
	    duty = calc_duty(mb_temp.fan_duty, mb_temp.duty_offset, max_temp,
			     &last_mb_v, &last_mb_duty);
	    if (duty > max_duty)
		max_duty = duty;
	}
	err = get_readings(sys, &front_temp, &max_temp);
	if (!err) {
	    duty = calc_duty(front_temp.fan_duty, front_temp.duty_offset,
			     max_temp, &last_front_v, &last_front_duty);
	    if (duty > max_duty)
		max_duty = duty;
	}

	duty = 0;
	for (i = 1; i < 9; i++) {
	    char filename[50];
	    int val;

	    sprintf(filename, "/sys/class/astfan/fan%u_input", i);
	    err = get_intval(filename, &val);
	    if (err) {
		sys->log(sys, OS_ERROR, NULL,
			 "Can't read fan speed for %s: %s", filename,
			 strerror(err));
		/* Can't read fan, better safe than sorry. */
		duty = 90;
		fan_fail[i - 1] = 1;
	    } else {
		/* A fan is failing. */
		if (val < 1000) {
		    fan_fail[i - 1] = 1;
		    duty = 90;
		} else
		    fan_fail[i - 1] = 0;
	    }
	}

	for (i = 0; i < 4; i++) {
	    if (fan_fail[i * 2] || fan_fail[i * 2 + 1])
		set_intval(fan_fail_led[i], 1);
	    else
		set_intval(fan_fail_led[i], 0);
	}

	if (duty > max_duty)
	    max_duty = duty;

	if (all_fans_duty)
	    max_duty = all_fans_duty;

	if (max_duty != last_duty) {
	    if (debug & 8)
		sys->log(sys, DEBUG, NULL, "Setting fan duty to %d",
			 max_duty);

	    for (i = 1; i < 5; i++) {
		char filename[50];

		sprintf(filename, "/sys/class/astfan/pwm%u", i);
		err = set_intval(filename, max_duty * 256 / 100);
		if (err)
		    sys->log(sys, OS_ERROR, NULL,
			     "Can't set fan duty %s to %d: %s",
			     filename, max_duty, strerror(err));
	    }
	}

	get_readings(sys, &system_sensors, NULL);

	scan_eeprom_sensors(sys);

	scan_ps_sensors(sys);

	pthread_mutex_lock(&scan_mutex);
	write(scan_pipe[1], &dummy, 1);
	pthread_cond_wait(&scan_cond, &scan_mutex);
	pthread_mutex_unlock(&scan_mutex);

	if (wdt_test_timer_ran) {
	    unsigned char data = 1;
	    err = write(wdt_fd, &data, 1);
	    if (err == -1) {
		sys->log(sys, OS_ERROR, NULL,
			 "Unable to write to watchdog timer: %s",
			 strerror(err));
	    }
	    wdt_test_timer_ran = 0;
	}

	/* Wait until poll_time seconds after the last scan started */
	sys->get_monotonic_time(sys, &now);
	diff_timeval(&wait, &next, &now);
	select(0, NULL, NULL, NULL, &wait);
    }

    return NULL;
}

static unsigned char
conv_value(struct sensor_info *info, int value)
{
    value -= info->sub;
    if (info->mult)
	value *= info->mult;
    if (info->div) {
	value += info->div / 2;
	value /= info->div;
    }
    if (value < 0)
	return 0;
    if (value > 255)
	return 255;
    return value;
}

static void
set_sensors_from_table(sys_data_t *sys, struct sensor_handling *h)
{
    unsigned int i, j;

    for (i = 0; h->switch_s[i].filename; i++) {
	if (debug & 4)
	    sys->log(sys, DEBUG, NULL, "process value %s: %d %d (%u)",
		     h->switch_s[i].filename, h->switch_valids[i],
		     h->switch_last_values[i],
		     conv_value(&h->switch_s[i],
				h->switch_last_values[i]));

	ipmi_mc_sensor_set_enabled(bmc_mc, 0,
				   h->switch_s[i].sensor_number,
				   h->switch_valids[i]);
	if (h->switch_valids[i]) {
	    ipmi_mc_sensor_set_value(bmc_mc, 0,
				     h->switch_s[i].sensor_number,
				     conv_value(&h->switch_s[i],
						h->switch_last_values[i]),
				     1);
	}
    }

    for (i = 0; h->board[i].filename; i++) {
	for (j = 0; j < NUM_BOARDS; j++) {
	    if (debug & 4)
		sys->log(sys, DEBUG, NULL, "process value %s (%d): %d %d (%u)",
			 h->board[i].filename, j + 1, h->board_valids[i][j],
			 h->board_last_values[i][j],
			 conv_value(&h->board[i],
				    h->board_last_values[i][j]));

	    ipmi_mc_sensor_set_enabled(boards[j].mc, 0,
				       h->board[i].sensor_number,
				       h->board_valids[i][j]);
	    if (h->board_valids[i][j])
		ipmi_mc_sensor_set_value(boards[j].mc, 0,
					 h->board[i].sensor_number,
					 conv_value(&h->board[i],
						    h->board_last_values[i][j]),
					 1);
	}
    }
}

static void
handle_eesense_data(sys_data_t *sys)
{
    unsigned int i, j;

    for (i = 0; i < NUM_BOARDS; i++) {
	
	ipmi_mc_sensor_set_enabled(boards[i].mc, 0, 20,
				   eesense_data_ready[i]);
	ipmi_mc_sensor_set_enabled(boards[i].mc, 0, 21,
				   eesense_data_ready[i]);
	if (!eesense_data_ready[i])
	    continue;
	for (j = 0; j < 1; j++)
	    ipmi_mc_sensor_set_bit(boards[i].mc, 0, 20, j,
				   ((cpu_errors[i] >> j) & 1), 1);
	for (j = 0; j < 8; j++)
	    ipmi_mc_sensor_set_bit(boards[i].mc, 0, 21, j,
				   ((dimm_errors[i] >> j) & 1), 1);
    }
}

#define PMBUS_NONE_BIT		(1 << 0)
#define PMBUS_CML_BIT		(1 << 1)
#define PMBUS_TEMP_BIT		(1 << 2)
#define PMBUS_VIN_UV_BIT	(1 << 3)
#define PMBUS_IOUT_OC_BIT	(1 << 4)
#define PMBUS_VOUT_OV_BIT	(1 << 5)
#define PMBUS_OFF_BIT		(1 << 6)
#define PMBUS_BUSY_BIT		(1 << 7)
#define PMBUS_UNKNOWN_BIT	(1 << 8)
#define PMBUS_OTHER_BIT		(1 << 9)
#define PMBUS_FANS_BIT		(1 << 10)
#define PMBUS_NOT_POWER_GOOD_BIT (1 << 11)
#define PMBUS_MRF_BIT		(1 << 12)
#define PMBUS_INPUT_BIT		(1 << 13)
#define PMBUS_I_P_OUT_BIT	(1 << 14)
#define PMBUS_VOUT_BIT		(1 << 15)

/*
 * This is a mask to convert the PMBus status work to the IPMI power
 * supply status bitmask.  Each entry in this array has a set of bits;
 * if one of those bits is set in the status work then the index of
 * the entry is a bit that should be set in the IPMI sensor.
 */
static uint16_t pm_word_to_ipmi[7] =
{
    0, /* presence is handled separately */
    0xffff, /* If anything is set we declare a fault */
    PMBUS_TEMP_BIT | PMBUS_FANS_BIT, /* Predictive failure */
    0, /* Input lost, nothing for this, only have "lost or out of range" */
    PMBUS_INPUT_BIT, /* Input lost or out of range */
    0, /* Out of range but present.  No bit for this, just previous. */
    0, /* Configuration error */
};

static void
handle_ps_status(int num)
{
    uint16_t val;
    unsigned int i;

    if (ps_status_good[num]) {
	val = 1; /* Present */
	for (i = 1; i < 7; i++)
	    val |= (!!(ps_status_word[num] & pm_word_to_ipmi[i])) << i;
    } else {
	val = 0; /* Not present */
    }

    for (i = 0; i < 7; i++)
	ipmi_mc_sensor_set_bit(bmc_mc, 0, 8 + num, i, (val >> i) & 1, 1);
}

static void
set_sensors_from_tables(int fd, void *cb_data)
{
    sys_data_t *sys = cb_data;
    unsigned int i;
    int temp = 0;
    unsigned char dummy;
    int rv;

    read(fd, &dummy, 1);

    set_sensors_from_table(sys, &main_temp);
    set_sensors_from_table(sys, &mb_temp);
    set_sensors_from_table(sys, &front_temp);
    set_sensors_from_table(sys, &system_sensors);
    handle_eesense_data(sys);
    handle_ps_status(0);
    handle_ps_status(1);

    /* Check for shutdown thresholds */
    if (switch_temp_sensor_valids[0])
	temp = switch_temp_sensor_last_values[0];
    if (switch_temp_sensor_valids[1] &&
	temp < switch_temp_sensor_last_values[1])
	temp = switch_temp_sensor_last_values[1];
    if (temp >= SWITCH_TEMP_SHUTDOWN * 1000) {
	sys->log(sys, INFO, NULL, "CRITICAL: Switch has exceeded temperature"
		 " threshold, powering down system");
	power_down_system(sys);
    }
    temp = 0;
    for (i = 0; i < NUM_BOARDS; i++) {
	if (board_front_sensor_valids[0][i] &&
	    board_front_sensor_last_values[0][i] > temp)
	    temp = board_front_sensor_last_values[0][i];
    }
    if (temp >= FRONT_TEMP_SHUTDOWN * 1000) {
	sys->log(sys, INFO, NULL, "CRITICAL: External environment exceeded"
		 " temperature threshold, raw value is %d, powering down"
		 " system", temp);
	power_down_system(sys);
    }

    for (i = 0; i < NUM_BOARDS; i++) {
	temp = 0;
	if (board_temp_sensor_valids[0][i])
	    temp = board_temp_sensor_last_values[0][i];
	if (board_temp_sensor_valids[1][i] &&
	    temp < board_temp_sensor_last_values[1][i])
	    temp = board_temp_sensor_last_values[1][i];
	if (temp >= BOARD_TEMP_SHUTDOWN * 1000) {
	    unsigned char val = 0;
	    if (board_temp_sensor_last_oor[i]) {
		sys->log(sys, INFO, NULL, "CRITICAL: Board %d has exceeded"
			 " temperature threshold, raw value is %d,"
			 " powering down",
			 i + 1, temp);
		set_chassis_control(NULL, CHASSIS_CONTROL_POWER, &val,
				    &boards[i]);
	    } else {
		sys->log(sys, INFO, NULL, "WARNING: Board %d has exceeded"
			 " temperature threshold, raw value is %d,"
			 " will check again before shutdown",
			 i + 1, temp);
		board_temp_sensor_last_oor[i]++;
	    }
	} else
	    board_temp_sensor_last_oor[i] = 0;

	if (boards[i].fru_data_ready_for_handling) {
	    boards[i].fru_data_ready_for_handling = 0;
	    handle_board_fru(sys, i);
	    rv = ipmi_mc_fru_sem_post(boards[i].mc, 0);
	    if (rv)
		sys->log(sys, OS_ERROR, NULL,
			 "Error posting board %d semaphore: %s", i + 1,
			 strerror(rv));
	}
    }

    pthread_mutex_lock(&scan_mutex);
    pthread_cond_signal(&scan_cond);
    pthread_mutex_unlock(&scan_mutex);
}

/**************************************************************************
 * Marvell OEM commands.
 *************************************************************************/

struct fru_write_data {
    sys_data_t *sys;
    unsigned int num;
};

/*
 * Writing FRU data is too slow to do in the main thread, so do it in
 * another thread.
 */
static void *
fru_write_thread(void *cb_data)
{
    struct fru_write_data *info = cb_data;
    sys_data_t *sys = info->sys;
    unsigned int num = info->num;
    unsigned char board_fru_data[2048];
    int fd, rv;

    pthread_detach(pthread_self());

    free(info);

    fd = open(BOARD_FRU_FILE, O_RDONLY);
    if (fd == -1) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to read board FRU file %s: %s",
		 BOARD_FRU_FILE, strerror(errno));
    }
    rv = read(fd, board_fru_data, sizeof(board_fru_data));
    if (rv == -1) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to read board FRU file %s: %s",
		 BOARD_FRU_FILE, strerror(errno));
	goto out_err;
    } else if (rv != sizeof(board_fru_data)) {
	sys->log(sys, OS_ERROR, NULL,
		 "board FRU file too small %s: %d",
		 BOARD_FRU_FILE, rv);
	goto out_err;
    }
    rv = write_eeprom(&board_i2c[num].fru, board_fru_data, 0,
		      sizeof(board_fru_data));
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Error writing board %d fru: %d", num, rv);
	goto out_err;
    }

    boards[num].fru_data_ready_for_handling = 1;
    return NULL;

  out_err:
    rv = ipmi_mc_fru_sem_post(boards[num].mc, 0);
    if (rv)
	sys->log(sys, OS_ERROR, NULL,
		 "Error posting board %d semaphore: %s", num + 1, strerror(rv));
    return NULL;
}

static void
handle_marvell_cmd(lmc_data_t    *mc,
		   msg_t         *msg,
		   unsigned char *rdata,
		   unsigned int  *rdata_len,
		   void          *cb_data)
{
    sys_data_t *sys = cb_data;
    char cmd[100];
    int rv;

    /*
     * Note that the calling function remove the IANA from the message
     * and inserts the IANA in the return message, we handle this like
     * a normal command.
     *
     * Start assuming success.
     */
    rdata[0] = 0;
    *rdata_len = 1;

    switch (msg->cmd) {
    case DISABLE_NETWORK_SRVC_CMD:
	if (check_msg_length(msg, 1, rdata, rdata_len))
	    break;
	snprintf(cmd, sizeof(cmd), "/etc/ipmi/netsrvc %d\n", msg->data[0]);
	rv = system(cmd);
	if (rv == -1) {
	    rdata[0] = 0xff;
	    rdata[1] = errno;
	    rdata[2] = 0;
	    *rdata_len = 3;
	} else if (rv) {
	    rdata[0] = 0xff;
	    rdata[1] = 0;
	    rdata[2] = rv;
	    *rdata_len = 3;
	}
	break;

    case RELOAD_BOARD_FRU_CMD:
    {
	struct fru_write_data *info;
	pthread_t tid;
	unsigned int num;

	if (check_msg_length(msg, 1, rdata, rdata_len))
	    return;

	num = msg->data[0] - 1;
	if (num >= NUM_BOARDS)
	    goto out_err;

	if (!boards[num].present)
	    goto out_err;

	rv = ipmi_mc_fru_sem_trywait(boards[num].mc, 0);
	if (rv) {
	    if (errno == EAGAIN)
		/* Already in progress. */
		goto out_good;

	    sys->log(sys, OS_ERROR, NULL,
		     "Unable to claim board %d FRU semaphore: %s",
		     num + 1, strerror(errno));
	    goto out_err;
	}

	info = malloc(sizeof(*info));
	if (!info)
	    goto out_err;
	info->sys = sys;
	info->num = num;

	rv = pthread_create(&tid, NULL, fru_write_thread, info);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "MVMOD: Unable to create fru write thread: %s",
		     strerror(rv));
	    free(info);
	    goto out_err;
	}
    }
    break;

    case SET_ALL_FANS_DUTY_CMD:
    {
	int duty;

	if (check_msg_length(msg, 1, rdata, rdata_len))
	    break;

	duty = msg->data[0];
	if (duty == 0)
	    ; /* Disable the duty by setting to zero */
	else if (duty < 30)
	    duty = 30; /* Minimum allowed fan duty */
	else if (duty > 100)
	    duty = 100;
	all_fans_duty = duty;
    }
    break;

    case GET_ALL_FANS_DUTY_CMD:
	rdata[1] = all_fans_duty;
	*rdata_len = 2;
	break;

    default:
	handle_invalid_cmd(mc, rdata, rdata_len);
	break;
    }

  out_good:
    return;

  out_err:
    rdata[0] = 0xff;
}

int
ipmi_sim_module_print_version(sys_data_t *sys, char *initstr)
{
    printf("IPMI Simulator Marvell AXP module version %s\n", PVERSION);
    return 0;
}

/*
 * An emulator command for simulating a change in the board's presense.
 */
static int simulate_board_presence(emu_out_t  *out,
				   emu_data_t *emu,
				   lmc_data_t *mc,
				   char       **toks)
{
    int rv;
    unsigned int board, present;
    const char *err;

    rv = get_uint(toks, &board, &err);
    if (!rv && ((board == 0 || board > NUM_BOARDS))) {
	err = "board number out of range";
	rv = EINVAL;
    }
    if (rv) {
	out->printf(out, "Invalid board number: %s\n", err);
	return EINVAL;
    }
    board--;
    rv = get_bool(toks, &present, &err);
    if (rv) {
	out->printf(out, "Invalid board presence value: %s\n", err);
	return EINVAL;
    }
    simulate_board_absent[board] = !present;
}


/**************************************************************************
 * BMC reset handling
 *************************************************************************/

static void
handle_cold_reset(lmc_data_t    *mc,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len,
		  void          *cb_data)
{
    sys_data_t *sys = cb_data;
    int rv;

    rv = set_intval(RESET_REASON_FILE, RESET_REASON_COLD_BOOT);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "MVMOD: Unable to write cold reset reason: %s",
		 strerror(rv));
    }

    system("reboot");
}

static void
handle_warm_reset(lmc_data_t    *mc,
		  msg_t         *msg,
		  unsigned char *rdata,
		  unsigned int  *rdata_len,
		  void          *cb_data)
{
    sys_data_t *sys = cb_data;
    int rv;

    rv = set_intval(RESET_REASON_FILE, RESET_REASON_WARM_BOOT);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "MVMOD: Unable to write warm reset reason: %s",
		 strerror(rv));
    }

    exit(1);
}

/*
 * This is a timer that is periodically called from the main thread,
 * it is basically used to tell if the main thread is running.
 */
static void
wdt_test_timeout(void *cb_data)
{
    struct timeval tv;
    sys_data_t *sys = cb_data;

    if (wdt_test_timer_ran)
	sys->log(sys, OS_ERROR, NULL, "MVMOD: WDT test timer not cleared");

    wdt_test_timer_ran = 1;
    tv.tv_sec = 4;
    tv.tv_usec = 0;
    sys->start_timer(wdt_test_timer, &tv);
}


/**************************************************************************
 * Module initialization
 *************************************************************************/

int
ipmi_sim_module_init(sys_data_t *sys, const char *initstr_i)
{
    unsigned int num;
    int rv;
    const char *c;
    char *next;
    int use_events = 1;
    struct timeval tv;
    int power_up_force = 0;
    char *initstr = strdup(initstr_i);
    int val;

    printf("IPMI Simulator Marvell AXP module version %s\n", PVERSION);

    if (!initstr) {
	sys->log(sys, SETUP_ERROR, NULL, "Error: MV: Out of memory");
	return ENOMEM;
    }

    c = mystrtok(initstr, " \t\n", &next);
    while (c) {
	if (strcmp(c, "noevents") == 0) {
	    use_events = 0;
	} else if (strcmp(c, "fork") == 0) {
	    fork_event_wait = 1;
	} else if (strncmp(c, "debug=", 6) == 0) {
	    debug = strtoul(c + 6, NULL, 0);
	} else if (strcmp(c, "forcecold") == 0) {
	    power_up_force = 1;
	} else if (strcmp(c, "forcewarm") == 0) {
	    power_up_force = 1;
	    cold_power_up = 0;
	} else if (strcmp(c, "disablewdt") == 0) {
	    disable_wdt = 1;
	} else if (strncmp(c, "poll_time=", 10) == 0) {
	    poll_time = strtoul(c + 10, NULL, 0);
	} else {
	    sys->log(sys, SETUP_ERROR, NULL, "Warning: MV: Unknown init"
		     " string: %s", c);
	}
	c = mystrtok(NULL, " \t\n", &next);
    }

    free(initstr);

    check_chassis_state(sys);

    rv = init_chassis(sys);
    if (rv)
	return rv;

    rv = pipe(scan_pipe);
    if (rv == -1) {
	int errval = errno;
	sys->log(sys, SETUP_ERROR, NULL, "MVMOD: Unable to open pipe");
	return errval;
    }
    rv = sys->add_io_hnd(sys, scan_pipe[0], set_sensors_from_tables, sys,
			 &scan_fd_id);
    if (rv) {
	int errval = errno;
	sys->log(sys, SETUP_ERROR, NULL,
		 "MVMOD: Unable to add I/O handler");
	close(scan_pipe[0]);
	close(scan_pipe[1]);
	return errval;
    }

    if (use_events) {
	ast_fd = open("/dev/event", O_RDWR);
	if (ast_fd == -1) {
	    int errval = errno;
	    sys->log(sys, SETUP_ERROR, NULL, "Unable to open /dev/event");
	    return errval;
	}
	if (fork_event_wait) {
	    int pipefds[2];
	    rv = pipe(pipefds);
	    if (rv == -1) {
		int errval = errno;
		close(ast_fd);
		sys->log(sys, SETUP_ERROR, NULL, "Unable to open pipe");
		return errval;
	    }
	    rv = fork();
	    if (rv == -1) {
		int errval = errno;
		close(ast_fd);
		close(pipefds[0]);
		close(pipefds[1]);
		sys->log(sys, SETUP_ERROR, NULL, "Unable to fork");
		return errval;
	    } else if (rv != 0) {
		/*
		 * Note that the main program runs as the child and
		 * the shim program runs as the parent.  This allows
		 * the shim program to catch the SIGCHLD and terminate
		 * if the main program goes away.  Otherwise the shim
		 * would be stuck waiting on an event and not
		 * terminate properly.
		 */
		close(pipefds[0]);
		ast1300_shim(sys, ast_fd, pipefds[1], rv);
	    }
	    close(ast_fd);
	    close(pipefds[1]);
	    ast_fd = pipefds[0];
	}

	rv = sys->add_io_hnd(sys, ast_fd, ast_evt, sys, &ast_fd_id);
	if (rv) {
	    int errval = errno;
	    sys->log(sys, SETUP_ERROR, NULL,
		     "MVMOD: Unable to add I/O handler");
	    close(ast_fd);
	    return errval;
	}
    }
    rv = sys->alloc_timer(sys, mv_timeout, sys, &mv_timer);
    if (rv) {
	int errval = errno;
	sys->log(sys, SETUP_ERROR, NULL, "MVMOD: Unable to create timer");
	return errval;
    } else {
	tv.tv_sec = 1;
	tv.tv_usec = 0;
	sys->start_timer(mv_timer, &tv);
    }

    rv = sys->alloc_timer(sys, board_power_timeout, sys, &power_timer);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to allocate board power timer: %s", strerror(rv));
	return rv;
    }

    if (!power_up_force) {
	rv = get_uintval(COLD_POWER_UP_IO, &cold_power_up);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL, "Warning: MV: Could not read %s"
		     " so assuming cold power up: %s", COLD_POWER_UP_IO,
		     strerror(errno));
	    cold_power_up = 1;
	} else if (cold_power_up) {
	    /* Save the setting in case we fail in startup */
	    set_intval(COLD_POWER_FILE, 1);
	} else {
	    /*
	     * Get the setting from the last startup.  If it's not
	     * there, no big deal.
	     */
	    get_uintval(COLD_POWER_FILE, &cold_power_up);
	}
    }

    rv = ipmi_mc_alloc_unconfigured(sys, 0x20, &bmc_mc);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to allocate an mc: %s", strerror(rv));
	return rv;
    }

    for (num = 0; num < NUM_BOARDS; num++) {
	lmc_data_t *mc;
	unsigned int rval = 0;
	struct board_info *board = &boards[num];

	board->num = num;
	board->sys = sys;

	board->last_power_request = BOARD_OFF_READY;
	if (!cold_power_up) {
	    /*
	     * On a cold power up, we bring everything up that is
	     * present.  Otherwise we run this code to read the
	     * current status and retain that.
	     */
	    rv = get_uintval(trg_present[num], &rval);
	    if (rv) {
		sys->log(sys, OS_ERROR, NULL,
			 "Unable to read board %u presense state: %s",
			 num, strerror(rv));
		return rv;
	    }
	    if (rval != BOARD_PRESENT) {
		unsigned char val = 0;
		set_chassis_control(NULL, CHASSIS_CONTROL_POWER, &val, board);
	    } else if (board_power_state(sys, num)) {
		/*
		 * This looks a bit unusual, so I will explain.  The
		 * board power request is only handled on a off-to-on
		 * transition, the raw values is not used directly.
		 * But this presents an issue at startup: what if the
		 * board requested a power off while this code wasn't
		 * running?  To solve that, if it is not a cold power
		 * up, assume that the request is off and then we will
		 * power down if the request is asserted.
		 */
		board->last_power_request = BOARD_OFF_NOT_READY;
	    }
	}

	rv = ipmi_mc_alloc_unconfigured(sys, board_ipmb[num], &mc);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "Unable to allocate an mc: %s", strerror(rv));
	    return rv;
	}
	boards[num].mc = mc;

	ipmi_mc_set_chassis_control_func(mc, set_chassis_control,
					 get_chassis_control, board);

	rv = check_board(sys, num, 0, cold_power_up);
	if (rv) {
	    if (ast_fd_id)
		sys->remove_io_hnd(ast_fd_id);
	    if (mv_timer)
		sys->free_timer(mv_timer);
	    return rv;
	}
    }

    ipmi_mc_set_chassis_control_func(bmc_mc, bmc_set_chassis_control,
				     bmc_get_chassis_control, sys);


    rv = ipmi_emu_register_iana_handler(MARVELL_SEMI_ISREAL_IANA,
					handle_marvell_cmd, sys);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to register Marvell IANA handler: %s", strerror(rv));
    }

    rv = ipmi_emu_register_cmd_handler(IPMI_APP_NETFN, IPMI_COLD_RESET_CMD,
				       handle_cold_reset, sys);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to register cold reset handler: %s", strerror(rv));
    }

    rv = ipmi_emu_register_cmd_handler(IPMI_APP_NETFN, IPMI_WARM_RESET_CMD,
				       handle_warm_reset, sys);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to register cold reset handler: %s", strerror(rv));
    }

    if (!disable_wdt) {
	wdt_fd = open("/dev/watchdog", O_WRONLY);
	if (wdt_fd == -1) {
	    sys->log(sys, OS_ERROR, NULL,
		     "Unable to open wdt: %s", strerror(errno));
	    return rv;
	}

	rv = sys->alloc_timer(sys, wdt_test_timeout, sys, &wdt_test_timer);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "Unable to allocate wdt test timer: %s", strerror(rv));
	    return rv;
	}
	tv.tv_sec = 4;
	tv.tv_usec = 0;
	sys->start_timer(wdt_test_timer, &tv);
    }

    if (!cold_power_up)
	init_complete = 1;

    ipmi_emu_add_cmd("simulate_board_presence", NOMC, simulate_board_presence);

    return 0;
}

int
ipmi_sim_module_post_init(sys_data_t *sys)
{
    int rv;
    const char *ver = get_lanserv_version();
    unsigned char lver[4];
    unsigned char omajor, ominor, orel;
    unsigned int i;
    int val;

    sscanf(ver, "%hhu.%hhu.%hhu", lver + 0, lver + 1, lver + 2);
    lver[3] = 0;
    sscanf(PVERSION, "%hhu.%hhu.%hhu", &omajor, &ominor, &orel);
    for (i = 0; i < NUM_BOARDS; i++) {
	ipmi_mc_set_fw_revision(boards[i].mc, omajor, ominor << 4 | orel);
	ipmi_mc_set_aux_fw_revision(boards[i].mc, lver);
    }
    ipmi_mc_set_fw_revision(bmc_mc, omajor, ominor << 4 | orel);
    ipmi_mc_set_aux_fw_revision(bmc_mc, lver);

    /*
     * Set the rearm handler for the CPU and DIMM sensors to clear
     * them on rearm.
     */
    
    for (i = 0; i < NUM_BOARDS; i++) {
	struct eesense_rearm *info;

	info = malloc(sizeof(*info));
	if (!info) {
	    sys->log(sys, OS_ERROR, NULL,
		     "MVMOD: Unable to allocate eesense handler for board %d: "
		     "Out of memory", i + 1);
	    continue;
	}
	info->num = i;
	info->offset = 1;
	info->mask = 0x01;
	rv = ipmi_mc_sensor_add_rearm_handler(boards[i].mc, 0, 20,
					      rearm_eesense_sensor, info);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "MVMOD: Error adding eesense CPU rearm on %d: %s",
		     i + 1, strerror(rv));
	    continue;
	}

	info = malloc(sizeof(*info));
	if (!info) {
	    sys->log(sys, OS_ERROR, NULL,
		     "MVMOD: Unable to allocate eesense handler for board %d: "
		     "Out of memory", i + 1);
	    continue;
	}
	info->num = i;
	info->offset = 2;
	info->mask = 0x87;
	rv = ipmi_mc_sensor_add_rearm_handler(boards[i].mc, 0, 21,
					      rearm_eesense_sensor, info);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "MVMOD: Error adding eesense DIMM rearm on %d: %s",
		     i + 1, strerror(rv));
	}
    }

    rv = ipmi_mc_sensor_add_rearm_handler(bmc_mc, 0, 8,
					  rearm_power_supply_sensor,
					  (void *) 1);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "MVMOD: Error adding power supply %d rearm: %s",
		 1, strerror(rv));
    }

    rv = ipmi_mc_sensor_add_rearm_handler(bmc_mc, 0, 9,
					  rearm_power_supply_sensor,
					  (void *) 2);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "MVMOD: Error adding power supply %d rearm: %s",
		 2, strerror(rv));
    }

    /* Initial state of the PSU sensor is with the present bit set */
    ipmi_mc_sensor_set_bit(bmc_mc, 0, 8, 0, 1, 0);
    ipmi_mc_sensor_set_bit(bmc_mc, 0, 9, 0, 1, 0);

    rv = pthread_create(&scan_thread, NULL, scan_sensors, sys);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "MVMOD: Unable to start scan thread: %s", strerror(rv));
    }

    rv = get_intval(RESET_REASON_FILE, &val);
    if (rv || cold_power_up) {
	val = 0x00; /* Initiated by power up */
    } else if (val == RESET_REASON_COLD_BOOT ||
	       rv || val == RESET_REASON_UNKNOWN) {
	val = 0x01; /* Initiated by hard reset */
    } else if (val == RESET_REASON_WARM_BOOT) {
	val = 0x02; /* Initiated by warm reset */
    } else {
	sys->log(sys, OS_ERROR, NULL, "MVMOD: known reset reason: %d", val);
	val = 0x01; /* Assume hard reset */
    }
    {
	/*
	 * We don't have an actual sensor for this, since it is
	 * event-only, just send the event.
	 */
	unsigned char data[13];
	memset(data, 0, sizeof(data));
	data[4] = ipmi_mc_get_ipmb(bmc_mc);
	data[5] = 0; /* LUN */
	data[6] = 0x04; /* Event message revision for IPMI 1.5. */
	data[7] = 0x1d; /* System boot initiated. */
	data[8] = 20; /* Sensor num */
	data[9] = (IPMI_ASSERTION << 7) | 0x6f;
	data[10] = val;
	rv = mc_new_event(bmc_mc, 0x02, data);
	if (rv)
	    sys->log(sys, OS_ERROR, NULL,
		     "MVMOD: Unable to add reboot cause event: %s, "
		     "event queue is probably full",
		     strerror(rv));

    }

    rv = set_intval(RESET_REASON_FILE, 0);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL,
		 "MVMOD: Unable to clear reset reason: %s",
		 strerror(rv));
    }

    return rv;
}
