/*
 * lanserv_config.c
 *
 * MontaVista IPMI code for reading lanserv configuration files.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003 MontaVista Software Inc.
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

#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <OpenIPMI/lanserv.h>
#include <string.h>
#include <netdb.h>

#ifndef IPMI_LAN_STD_PORT_STR
#define IPMI_LAN_STD_PORT_STR	"623"
#endif

static int
get_bool(char **tokptr, unsigned int *rval, char **err)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);

    if (!tok)
	return -1;
    if (strcasecmp(tok, "true") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "false") == 0)
	*rval = 0;
    else if (strcasecmp(tok, "on") == 0)
	*rval = 1;
    else if (strcasecmp(tok, "off") == 0)
	*rval = 0;
    else {
	*err = "Invalid boolean value, must be 'true', 'on', 'false', or 'off'";
	return -1;
    }

    return 0;
}

static int
get_priv(char **tokptr, unsigned int *rval, char **err)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);

    if (!tok) {
	*err = "No privilege specified, must be 'callback', 'user',"
	    " 'operator', or 'admin'";
	return -1;
    }
    if (strcmp(tok, "callback") == 0)
	*rval = IPMI_PRIVILEGE_CALLBACK;
    else if (strcmp(tok, "user") == 0)
	*rval = IPMI_PRIVILEGE_USER;
    else if (strcmp(tok, "operator") == 0)
	*rval = IPMI_PRIVILEGE_OPERATOR;
    else if (strcmp(tok, "admin") == 0)
	*rval = IPMI_PRIVILEGE_ADMIN;
    else {
	*err = "Invalid privilege specified, must be 'callback', 'user',"
	    " 'operator', or 'admin'";
	return -1;
    }

    return 0;
}

static int
get_auths(char **tokptr, unsigned int *rval, char **err)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);
    int  val = 0;

    while (tok) {
	if (strcmp(tok, "none") == 0)
	    val |= (1 << IPMI_AUTHTYPE_NONE);
	else if (strcmp(tok, "md2") == 0)
	    val |= (1 << IPMI_AUTHTYPE_MD2);
	else if (strcmp(tok, "md5") == 0)
	    val |= (1 << IPMI_AUTHTYPE_MD5);
	else if (strcmp(tok, "straight") == 0)
	    val |= (1 << IPMI_AUTHTYPE_STRAIGHT);
	else {
	    *err = "Invalid authorization type, must be 'none', 'md2',"
		" 'md5', or 'straight'";
	    return -1;
	}

	tok = strtok_r(NULL, " \t\n", tokptr);
    }

    *rval = val;

    return 0;
}

static int
get_uint(char **tokptr, unsigned int *rval, char **err)
{
    char *end;
    char *tok = strtok_r(NULL, " \t\n", tokptr);

    *rval = strtoul(tok, &end, 0);
    if (*end != '\0') {
	*err = "Invalid integer value";
	return -1;
    }
    return 0;
}

static void
cleanup_ascii_16(uint8_t *c)
{
    int i;

    i = 0;
    while ((i < 16) && (*c != 0)) {
	c++;
	i++;
    }
    while (i < 16) {
	*c = 0;
	c++;
	i++;
    }
}

static int
read_16(char **tokptr, unsigned char *data, char **err)
{
    char *tok = strtok_r(NULL, " \t\n", tokptr);
    char *end;

    if (!tok) {
	*err = "Missing password or username";
	return -1;
    }
    if (*tok == '"') {
	int end;
	/* Ascii PW */
	tok++;
	end = strlen(tok) - 1;
	if (tok[end] != '"') {
	    *err = "ASCII password or username doesn't end in '\"'";
	    return -1;
	}
	tok[end] = '\0';
	strncpy(data, tok, 16);
	cleanup_ascii_16(data);
    } else {
	int  i;
	char c[3];
	/* HEX pw */
	if (strlen(tok) != 32) {
	    *err = "HEX password or username not 32 HEX characters long";
	    return -1;
	}
	c[2] = '\0';
	for (i=0; i<16; i++) {
	    c[0] = *tok;
	    tok++;
	    c[1] = *tok;
	    tok++;
	    data[i] = strtoul(c, &end, 16);
	    if (*end != '\0') {
		*err = "Invalid HEX character in password or username";
		return -1;
	    }
	}
    }

    return 0;
}

static int
get_user(char **tokptr, lan_data_t *lan, char **err)
{
    unsigned int num;
    unsigned int val;
    int          rv;

    rv = get_uint(tokptr, &num, err);
    if (rv)
	return rv;

    if (num > MAX_USERS) {
	*err = "User number larger than the allowed number of users";
	return -1;
    }

    rv = get_bool(tokptr, &val, err);
    if (rv)
	return rv;
    lan->users[num].valid = val;

    rv = read_16(tokptr, lan->users[num].username, err);
    if (rv)
	return rv;

    rv = read_16(tokptr, lan->users[num].pw, err);
    if (rv)
	return rv;

    rv = get_priv(tokptr, &val, err);
    if (rv)
	return rv;
    lan->users[num].privilege = val;

    rv = get_uint(tokptr, &val, err);
    if (rv)
	return rv;
    lan->users[num].max_sessions = val;

    rv = get_auths(tokptr, &val, err);
    if (rv)
	return rv;
    lan->users[num].allowed_auths = val;

    return 0;
}

static int
get_sock_addr(char **tokptr, sockaddr_ip_t *addr, socklen_t *len, char **err)
{
    char *s, *p;

    s = strtok_r(NULL, " \t\n", tokptr);
    if (!s) {
	*err = "No IP address specified";
	return -1;
    }
    p = strtok_r(NULL, " \t\n", tokptr);

#ifdef HAVE_GETADDRINFO
    {
	struct addrinfo     hints, *res0;
	int rv;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = PF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE;
	if (p) {
	    rv = getaddrinfo(s, p, &hints, &res0);
	} else {
	    rv = getaddrinfo(s, IPMI_LAN_STD_PORT_STR, &hints, &res0);
	}
	if (rv) {
	    *err = "getaddrinfo err";
	    return -1;
	}
	memcpy(addr, res0->ai_addr, res0->ai_addrlen);
	*len = res0->ai_addrlen;
	freeaddrinfo(res0);
    }
#else
    /* System does not support getaddrinfo, just for IPv4*/
    {
	struct hostent     *ent;
	struct sockaddr_in *paddr;
        char               *end;

	ent = gethostbyname(s);
	if (!ent) {
	    *err = "Invalid IP address specified";
	    return -1;
	}

	paddr = (struct sockaddr_in *)addr;
	paddr->sin_family = AF_INET;
	if (p) {
	    paddr->sin_port = htons(strtoul(p, &end, 0));
	    if (*end != '\0') {
	        *err = "Invalid IP port specified";
	        return -1;
	    }
	} else {
	    paddr->sin_port = htons(623);
	}
	*len = sizeof(struct sockaddr_in);
    }
#endif
    return 0;
}

#define MAX_CONFIG_LINE 256
int
lanserv_read_config(lan_data_t    *lan,
		    char          *config_file,
		    sockaddr_ip_t addr[],
		    socklen_t     addr_len[],
		    int           *num_addr)
{
    FILE         *f = fopen(config_file, "r");
    char         buf[MAX_CONFIG_LINE];
    char         *tok;
    char         *tokptr;
    unsigned int val;
    int          err = 0;
    int          line;
    char         *errstr;
    int          max_addr = *num_addr;

    *num_addr = 0;
    if (!f) {
	fprintf(stderr, "Unable to open configuration file '%s'\n",
		config_file);
	return -1;
    }

    line = 0;
    while (fgets(buf, sizeof(buf), f) != NULL) {
	line++;

	if (buf[0] == '#')
	    continue;
	tok = strtok_r(buf, " \t\n", &tokptr);
	if (!tok)
	    continue;

	if (strcmp(tok, "PEF_alerting") == 0) {
	    err = get_bool(&tokptr, &val, &errstr);
	    lan->channel.PEF_alerting = val;
	} else if (strcmp(tok, "per_msg_auth") == 0) {
	    err = get_bool(&tokptr, &val, &errstr);
	    lan->channel.per_msg_auth = val;
	} else if (strcmp(tok, "priv_limit") == 0) {
	    err = get_priv(&tokptr, &val, &errstr);
	    lan->channel.privilege_limit = val;
	} else if (strcmp(tok, "allowed_auths_callback") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[0].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_user") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[1].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_operator") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[2].allowed_auths = val;
	} else if (strcmp(tok, "allowed_auths_admin") == 0) {
	    err = get_auths(&tokptr, &val, &errstr);
	    lan->channel.priv_info[3].allowed_auths = val;
	} else if (strcmp(tok, "addr") == 0) {
	    if (*num_addr >= max_addr) {
		fprintf(stderr, "Too many addresses specified\n");
		err = EINVAL;
	    }
	    err = get_sock_addr(&tokptr, &addr[*num_addr],
				&addr_len[*num_addr],
				&errstr);
	    (*num_addr)++;
	} else if (strcmp(tok, "user") == 0) {
	    err = get_user(&tokptr, lan, &errstr);
	} else if (strcmp(tok, "guid") == 0) {
	    if (!lan->guid)
		lan->guid = malloc(16);
	    if (!lan->guid)
		return -1;
	    err = read_16(&tokptr, lan->guid, &errstr);
	    if (err) {
	        fprintf(stderr, "Error on line %d: %s\n", line, errstr);
		return err;
	    }	
	} else {
	    errstr = "Invalid configuration option";
	    err = -1;
	}

	if (err) {
	    fprintf(stderr, "Error on line %d: %s\n", line, errstr);
	    return err;
	}
    }

    return 0;
}
