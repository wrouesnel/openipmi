/*
 * glibshim.c
 *
 * A SWIG glib shim for OpenIPMI
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2006 MontaVista Software Inc.
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
#include <OpenIPMI/ipmi_glib.h>
#include <OpenIPMI/ipmiif.h>
#include <OpenIPMI/ipmi_cmdlang.h>
#include <glib.h>
#include <dlfcn.h>
#include <stdio.h>
#include <malloc.h>

void glib_do_log(const char *pfx, const char *message);

void openipmi_swig_vlog(os_handler_t *os_handler, const char *format,
			enum ipmi_log_type_e log_type, va_list ap);

#define join3_2(a, b, c) a##b##c
#define join3(a, b, c) join3_2(a, b, c)
#define strify_2(a) #a
#define strify(a) strify_2(a)

static void
glib_handle_log(const char *domain,
		const char *pfx,
		const char *message)
{
    glib_do_log(pfx, message);
}

static char *olibst = "libOpenIPMIglib%s.so";

/*
 * Initialize the OS handler with the glib version.
 */
os_handler_t *
init_glib_shim(char *ver)
{
    os_handler_t *swig_os_hnd;
    char         dummy[1];
    char         *name;
    void         *hndl;
    os_handler_t *(*get)(int);
    void         (*setlog)(void (*hndlr)(const char *domain,
					 const char *pfx,
					 const char *msg));
    int          len;

    len = snprintf(dummy, 1, olibst, ver);
    name = malloc(len+1);
    if (!name)
	return NULL;
    snprintf(name, len+1, olibst, ver);
    printf("A: %s\n", name);
    hndl = dlopen(name, 0);
    free(name);
    if (!hndl)
	return NULL;
    printf("B\n");
    get = dlsym(hndl, "ipmi_glib_get_os_handler");
    if (!get)
	return NULL;
    printf("C\n");
    setlog = dlsym(hndl, "ipmi_glib_set_log_handler");
    if (!setlog)
	return NULL;
    printf("D\n");

    swig_os_hnd = get(0);
    swig_os_hnd->set_log_handler(swig_os_hnd, openipmi_swig_vlog);
    ipmi_init(swig_os_hnd);
    ipmi_cmdlang_init(swig_os_hnd);
    setlog(glib_handle_log);
    return swig_os_hnd;
}

