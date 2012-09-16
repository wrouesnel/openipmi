/*
 * extcmd.c
 *
 * MontaVista IPMI IPMI LAN interface extern command handler
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2012 MontaVista Software Inc.
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ether.h>
#include <ctype.h>
#include <string.h>
#include <errno.h>
#include <stdio.h>
#include <malloc.h>

#include <OpenIPMI/serv.h>
#include <OpenIPMI/extcmd.h>

static int
extcmd_getval(void *baseloc, extcmd_info_t *t, char *val)
{
    unsigned char *loc = baseloc;

    while (isspace(*val))
	val++;

    loc += t->offset;

    switch (t->type) {
    case extcmd_ip:
	if (inet_aton(val, (struct in_addr *) loc) == 0)
	    return EINVAL;
	break;

    case extcmd_mac:
	if (ether_aton_r(val, (struct ether_addr *) loc) == 0)
	    return EINVAL;
	break;

    case extcmd_ip_src:
	if (strncmp(val, "unknown", 7) == 0)
	    *loc = 0;
	else if (strncmp(val, "static", 6) == 0)
	    *loc = 1;
	else if (strncmp(val, "dhcp", 4) == 0)
	    *loc = 2;
	else if (strncmp(val, "bios", 4) == 0)
	    *loc = 3;
	else if (strncmp(val, "other", 5) == 0)
	    *loc = 4;
	else
	    return EINVAL;
	break;

    default:
	return EINVAL;
    }

    return 0;
}

static char *
extcmd_setval(void *baseloc, extcmd_info_t *t)
{
    unsigned char *loc = baseloc;
    char buf[18]; /* Big enough to hold IP, MAC and src */

    loc += t->offset;

    switch (t->type) {
    case extcmd_ip:
	if (!inet_ntop(AF_INET, loc, buf, sizeof(buf)))
	    return NULL;
	break;

    case extcmd_mac:
	if (!ether_ntoa_r((struct ether_addr *) loc, buf))
	    return NULL;
	break;

    case extcmd_ip_src:
	switch (*loc) {
	case 0:
	    strcpy(buf, "unknown");
	    break;

	case 1:
	    strcpy(buf, "static");
	    break;

	case 2:
	    strcpy(buf, "dhcp");
	    break;

	case 3:
	    strcpy(buf, "bios");
	    break;

	case 4:
	    strcpy(buf, "other");
	    break;

	default:
	    return NULL;
	}
	break;

    default:
	return NULL;
    }

    return strdup(buf);
}

static int
process_extcmd_value(void *baseloc, extcmd_info_t *t, char *buf)
{
    while (buf) {
	unsigned int len = strlen(t->name);

	if ((strncmp(buf, t->name, len) == 0) && buf[len] == ':')
	    return extcmd_getval(baseloc, t, buf + len + 1);
	buf = strchr(buf, '\n') + 1;
    }
    return EEXIST;
}

static int
add_cmd(char **cmd, char *name,	char *value, int freevalue)
{
    unsigned int size;
    char *newcmd;
    int rv = 0;

    if (freevalue && !value) {
	rv = EINVAL;
	goto out;
    }

    size = strlen(name) + 1;
    if (value)
	size += strlen(value) + 3;
    size += strlen(*cmd);

    newcmd = malloc(size + 1);
    if (!newcmd) {
	rv = ENOMEM;
	goto out;
    }

    strcpy(newcmd, *cmd);
    free(*cmd);
    strcat(newcmd, " ");
    strcat(newcmd, name);
    if (value) {
	strcat(newcmd, " \"");
	strcat(newcmd, value);
	strcat(newcmd, "\"");
    }
    *cmd = newcmd;
	
  out:
    if (freevalue)
	free(value);
    return rv;
}

int
extcmd_getvals(sys_data_t *sys,
	       void *baseloc, char *cmd, extcmd_info_t *ts, unsigned int count)
{
    int rv;
    char *newcmd;
    FILE *f;
    unsigned int i;
    char buf[2048];
    unsigned int buflen = sizeof(buf);

    if (!cmd)
	return 0;

    newcmd = malloc(strlen(cmd) + 5);
    if (!newcmd)
	return ENOMEM;
    strcpy(newcmd, cmd);
    strcat(newcmd, " get");
    cmd = newcmd;

    for (i = 0; i < count; i++) {
	rv = add_cmd(&cmd, ts[i].name, NULL, 0);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "Out of memory in extcmd read command\n");
	    goto out;
	}
    }

    f = popen(cmd, "r");
    if (!f) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to execute extcmd read command (%s): %s\n",
		 cmd, strerror(errno));
	rv = errno;
	goto out;
    }

    rv = fread(buf, 1, buflen - 1, f);
    if ((unsigned int) rv == buflen - 1) {
	sys->log(sys, OS_ERROR, NULL,
		 "Output of extcmd config read command (%s) is too big", cmd);
	rv = EINVAL;
	goto out;
    }
    buf[rv] = '\0';

    rv = pclose(f);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL, 
		 "extcmd read command (%s) failed: %x: %s", cmd, rv, buf);
	goto out;
    }

    for (i = 0; i < count; i++) {
	rv = process_extcmd_value(baseloc, ts + i, buf);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "Setting extern command value of %s failed: %s",
		     ts[i].name, strerror(rv));
	    goto out;
	}
    }
  out:
    free(cmd);
    return rv;
}

int
extcmd_setvals(sys_data_t *sys,
	       void *baseloc, char *cmd, extcmd_info_t *ts,
	       unsigned char *setit, unsigned int count)
{
    int rv = 0;
    char *newcmd;
    FILE *f;
    unsigned int i;
    char buf[2048];
    unsigned int buflen = sizeof(buf);
    int oneset = 0;

    if (!cmd)
	return 0;

    newcmd = malloc(strlen(cmd) + 5);
    if (!newcmd)
	return ENOMEM;
    strcpy(newcmd, cmd);
    strcat(newcmd, " set");
    cmd = newcmd;

    for (i = 0; i < count; i++) {
	if (!setit[i])
	    continue;
	oneset = 1;
	rv = add_cmd(&cmd, ts[i].name, extcmd_setval(baseloc, ts + i), 1);
	if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "Out of memory in extcmd write command\n");
	    goto out;
	}
    }
    if (!oneset)
	goto out;

    f = popen(cmd, "r");
    if (!f) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to execute extcmd write command (%s): %s\n",
		 cmd, strerror(errno));
	rv = errno;
	goto out;
    }

    rv = fread(buf, 1, buflen - 1, f);
    if ((unsigned int) rv == buflen - 1) {
	sys->log(sys, OS_ERROR, NULL,
		 "Output of extcmd config write command (%s) is too big", cmd);
	rv = EINVAL;
	goto out;
    }
    buf[rv] = '\0';

    rv = pclose(f);
    if (rv) {
	sys->log(sys, OS_ERROR, NULL, 
		 "extcmd write command (%s) failed: %x: %s", cmd, rv, buf);
	goto out;
    }

  out:
    free(cmd);
    return rv;
}

int
extcmd_checkvals(sys_data_t *sys,
		 void *baseloc, char *cmd, extcmd_info_t *ts,
		 unsigned int count)
{
    int rv = 0;
    char *newcmd;
    FILE *f;
    unsigned int i;
    char buf[2048];
    unsigned int buflen = sizeof(buf);

    if (!cmd)
	return 0;

    newcmd = malloc(strlen(cmd) + 7);
    if (!newcmd)
	return ENOMEM;
    strcpy(newcmd, cmd);
    strcat(newcmd, " check");
    cmd = newcmd;

    for (i = 0; i < count; i++) {
	rv = add_cmd(&cmd, ts[i].name, extcmd_setval(baseloc, ts + i), 1);
	if (rv == ENOMEM) {
	    sys->log(sys, OS_ERROR, NULL,
		     "Out of memory in extcmd check command\n");
	    goto out;
	} else if (rv) {
	    sys->log(sys, OS_ERROR, NULL,
		     "Invalid value in extcmd check command for %s\n",
		     ts[i].name);
	    goto out;
	}
    }

    f = popen(cmd, "r");
    if (!f) {
	sys->log(sys, OS_ERROR, NULL,
		 "Unable to execute extcmd check command (%s): %s\n",
		 cmd, strerror(errno));
	rv = errno;
	goto out;
    }

    rv = fread(buf, 1, buflen - 1, f);
    if ((unsigned int) rv == buflen - 1) {
	sys->log(sys, OS_ERROR, NULL,
		 "Output of extcmd config check command (%s) is too big", cmd);
	rv = EINVAL;
	goto out;
    }
    buf[rv] = '\0';

    /* Return value should tell us if it's ok. */
    rv = pclose(f);

  out:
    free(cmd);
    return rv;
}
