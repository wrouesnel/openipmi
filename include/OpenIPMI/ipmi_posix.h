/*
 * os_handler.h
 *
 * MontaVista IPMI os handler interface.
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

#ifndef __IPMI_POSIX_H
#define __IPMI_POSIX_H

#include <OpenIPMI/os_handler.h>
#include <OpenIPMI/selector.h>

/* These are the defined OS handlers for POSIX with and without
   threading.  If you use these (and thus link with the OpenIPMIposix
   or OpenIPMIpthread libraries) you must provide posix_vlog().  It is
   not provided by the library. */
void posix_vlog(char *format,
		enum ipmi_log_type_e log_type,
		va_list ap);
os_handler_t *ipmi_posix_get_os_handler(void);
void ipmi_posix_os_handler_set_sel(os_handler_t *os_hnd, selector_t *sel);

os_handler_t *ipmi_posix_thread_get_os_handler(void);
void ipmi_posix_thread_os_handler_set_sel(os_handler_t *os_hnd,
					  selector_t   *sel);

#endif /* __IPMI_POSIX_H */
