/*
 * ipmi.c
 *
 * MontaVista IPMI generic code
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

#include <string.h>
#include <errno.h>

#include <OpenIPMI/ipmi_auth.h>
#include <OpenIPMI/ipmi_err.h>
#include <OpenIPMI/ipmi_int.h>
#include "md2.h"
#include "md5.h"

static int
pw_authcode_init(unsigned char *password, ipmi_authdata_t *handle)
{
    unsigned char *data;

    data = ipmi_mem_alloc(16);
    if (!data)
	return ENOMEM;

    memcpy(data, password, 16);
    *handle = (ipmi_authdata_t) data;
    return 0;
}

static int
pw_authcode_gen(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *output)
{
    memcpy(output, handle, 16);
    return 0;
}

static int
pw_authcode_check(ipmi_authdata_t handle, ipmi_auth_sg_t data[], void *code)
{
    if (strncmp((unsigned char *) handle, code, 16) != 0)
	return EINVAL;
    return 0;
}

static void
pw_authcode_cleanup(ipmi_authdata_t handle)
{
    ipmi_mem_free(handle);
}

static int
no_authcode_init(unsigned char *password, ipmi_authdata_t *handle)
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

