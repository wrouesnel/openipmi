/*
 * ipmi_auth.c
 *
 * MontaVista IPMI authentication
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004,2005 MontaVista Software Inc.
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

#include <string.h>
#include <errno.h>

#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/internal/md2.h>
#include <OpenIPMI/internal/md5.h>

struct ipmi_authdata_s
{
    void          *info;
    void          *(*mem_alloc)(void *info, int size);
    void          (*mem_free)(void *info, void *data);
    unsigned char data[16];
};

static int
pw_authcode_init(unsigned char   *password,
		 ipmi_authdata_t *handle,
		 void            *info,
		 void            *(*mem_alloc)(void *info, int size),
		 void            (*mem_free)(void *info, void *data))
{
    struct ipmi_authdata_s *data;

    data = mem_alloc(info, sizeof(*data));
    if (!data)
	return ENOMEM;

    data->info = info;
    data->mem_alloc = mem_alloc;
    data->mem_free = mem_free;

    memcpy(data->data, password, 16);
    *handle = data;
    return 0;
}

static int
pw_authcode_gen(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *output)
{
    memcpy(output, handle->data, 16);
    return 0;
}

static int
pw_authcode_check(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *code)
{
    if (strncmp((char *) handle->data, code, 16) != 0)
	return EINVAL;
    return 0;
}

static void
pw_authcode_cleanup(ipmi_authdata_t handle)
{
    memset(handle->data, 0, sizeof(handle->data));
    handle->mem_free(handle->info, handle);
}

static int
no_authcode_init(unsigned char   *password,
		 ipmi_authdata_t *handle,
		 void            *info,
		 void            *(*mem_alloc)(void *info, int size),
		 void            (*mem_free)(void *info, void *data))
{
    return 0;
}

static int
no_authcode_gen(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *output)
{
    memset(output, 0, 16);
    return 0;
}

static int
no_authcode_check(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *code)
{
    return 0;
}

static void
no_authcode_cleanup(ipmi_authdata_t handle)
{
}


ipmi_auth_t ipmi_auths[MAX_IPMI_AUTHS] =
{
    { no_authcode_init,  no_authcode_gen,
      no_authcode_check, no_authcode_cleanup },
    { ipmi_md2_authcode_init,  ipmi_md2_authcode_gen,
      ipmi_md2_authcode_check, ipmi_md2_authcode_cleanup },
    { ipmi_md5_authcode_init,  ipmi_md5_authcode_gen,
      ipmi_md5_authcode_check, ipmi_md5_authcode_cleanup },
    { NULL, NULL, NULL, NULL },
    { pw_authcode_init,  pw_authcode_gen,
      pw_authcode_check, pw_authcode_cleanup },
    { NULL, NULL, NULL, NULL },
};

