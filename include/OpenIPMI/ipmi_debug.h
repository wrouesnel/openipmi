/*
 * ipmi_debug.h
 *
 * MontaVista IPMI interface, debug information.
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2002,2003,2004 MontaVista Software Inc.
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

#ifndef _IPMI_DEBUG_H
#define _IPMI_DEBUG_H

extern unsigned int __ipmi_log_mask;

/* Log normal IPMI messages, but not low-level protocol messages. */
#define DEBUG_MSG_BIT		(1 << 0)

/* Log all messages. */
#define DEBUG_RAWMSG_BIT	(1 << 1)

/* Log events that are received. */
#define DEBUG_EVENTS_BIT	(1 << 3)

/* Force the given connection to no longer work */
#define DEBUG_CON0_FAIL_BIT	(1 << 4)
#define DEBUG_CON1_FAIL_BIT	(1 << 5)
#define DEBUG_CON2_FAIL_BIT	(1 << 6)
#define DEBUG_CON3_FAIL_BIT	(1 << 7)

#define DEBUG_MSG_ERR_BIT	(1 << 8)

#define DEBUG_MSG	(__ipmi_log_mask & DEBUG_MSG_BIT)
#define DEBUG_MSG_ENABLE() __ipmi_log_mask |= DEBUG_MSG_BIT
#define DEBUG_MSG_DISABLE() __ipmi_log_mask &= ~DEBUG_MSG_BIT

#define DEBUG_RAWMSG	(__ipmi_log_mask & DEBUG_RAWMSG_BIT)
#define DEBUG_RAWMSG_ENABLE() __ipmi_log_mask |= DEBUG_RAWMSG_BIT
#define DEBUG_RAWMSG_DISABLE() __ipmi_log_mask &= ~DEBUG_RAWMSG_BIT

#define DEBUG_EVENTS	(__ipmi_log_mask & DEBUG_EVENTS_BIT)
#define DEBUG_EVENTS_ENABLE() __ipmi_log_mask |= DEBUG_EVENTS_BIT
#define DEBUG_EVENTS_DISABLE() __ipmi_log_mask &= ~DEBUG_EVENTS_BIT

#define DEBUG_CON_FAIL(con)    (__ipmi_log_mask & (DEBUG_CON0_FAIL_BIT << con))
#define DEBUG_CON_FAIL_ENABLE(con) \
	__ipmi_log_mask |= (DEBUG_CON0_FAIL_BIT << con)
#define DEBUG_CON_FAIL_DISABLE(con) \
	__ipmi_log_mask &= ~(DEBUG_CON0_FAIL_BIT << con)

#define DEBUG_MSG_ERR	(__ipmi_log_mask & DEBUG_MSG_ERR_BIT)
#define DEBUG_MSG_ERR_ENABLE() __ipmi_log_mask |= DEBUG_MSG_ERR_BIT
#define DEBUG_MSG_ERR_DISABLE() __ipmi_log_mask &= ~DEBUG_MSG_ERR_BIT

#ifdef IPMI_CHECK_LOCKS
void ipmi_report_lock_error(os_handler_t *handler, char *str);
#define IPMI_REPORT_LOCK_ERROR(handler, str) ipmi_report_lock_error(handler, \
								    str)
#else
#define IPMI_REPORT_LOCK_ERROR(handler, str) do {} while (0)
#endif

extern int __ipmi_debug_locks;
#define DEBUG_LOCKS	(__ipmi_debug_locks)
#define DEBUG_LOCKS_ENABLE() __ipmi_debug_locks = 1
#define DEBUG_LOCKS_DISABLE() __ipmi_debug_locks = 0

#endif /* _IPMI_DEBUG_H */
