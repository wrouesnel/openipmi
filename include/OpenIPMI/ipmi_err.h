/*
 * ipmi_err.h
 *
 * MontaVista IPMI interface, error values.
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

#ifndef _IPMI_ERR_H
#define _IPMI_ERR_H

/*
 * Error values
 *
 * Return errors or reported errors can be due to OS problems or to 
 * reported IPMI errors for messages this code handled.  These macros
 * differentiate these.  Note that this is NOT for handling the first
 * byte of a response (the completion code) on a message you handle, it
 * will simply be a byte of information.
 */
#define IPMI_OS_ERR_TOP		0x00000000
#define IPMI_IPMI_ERR_TOP	0x01000000
#define IPMI_IS_OS_ERR(E)	(((E) & 0xffffff00) == IPMI_OS_ERR_TOP)
#define IPMI_GET_OS_ERR(E)	((E) & 0xff)
#define IPMI_OS_ERR_VAL(v)	((v) | IMPI_OS_ERR_TOP)
#define IPMI_IS_IPMI_ERR(E)	(((E) & 0xffffff00) == IPMI_IPMI_ERR_TOP)
#define IPMI_GET_IPMI_ERR(E)	((E) & 0xff)
#define IPMI_IPMI_ERR_VAL(v)	((v) | IPMI_IPMI_ERR_TOP)

/*
 * Completion codes for IPMI.
 */
#define IPMI_NODE_BUSY_CC			0xC0
#define IPMI_INVALID_CMD_CC			0xC1
#define IPMI_COMMAND_INVALID_FOR_LUN_CC		0xC2
#define IPMI_TIMEOUT_CC				0xC3
#define IPMI_OUT_OF_SPACE_CC			0xC4
#define IPMI_INVALID_RESERVATION_CC		0xC5
#define IPMI_REQUEST_DATA_TRUNCATED_CC		0xC6
#define IPMI_REQUEST_DATA_LENGTH_INVALID_CC	0xC7
#define IPMI_REQUESTED_DATA_LENGTH_EXCEEDED_CC	0xC8
#define IPMI_PARAMETER_OUT_OF_RANGE_CC		0xC9
#define IPMI_CANNOT_RETURN_REQ_LENGTH_CC	0xCA
#define IPMI_NOT_PRESENT_CC			0xCB
#define IPMI_INVALID_DATA_FIELD_CC		0xCC
#define IPMI_COMMAND_ILLEGAL_FOR_SENSOR_CC	0xCD
#define IPMI_COULD_NOT_PROVIDE_RESPONSE_CC	0xCE
#define IPMI_CANNOT_EXEC_DUPLICATE_REQUEST_CC	0xCF
#define IPMI_REPOSITORY_IN_UPDATE_MODE_CC	0xD0
#define IPMI_DEVICE_IN_FIRMWARE_UPDATE_CC	0xD1
#define IPMI_BMC_INIT_IN_PROGRESS_CC		0xD2
#define IPMI_DESTINATION_UNAVAILABLE_CC		0xD3
#define IPMI_INSUFFICIENT_PRIVILEGE_CC		0xD4
#define IPMI_NOT_SUPPORTED_IN_PRESENT_STATE_CC	0xD5
#define IPMI_UNKNOWN_ERR_CC			0xff

/* Convert a completion code into a string.  You must pass a buffer in
   (32 bytes is good) and the buffer length.  The string will be
   stored in that buffer and also returned. */
char *ipmi_get_cc_string(unsigned int cc,
			 char         *buffer,
			 unsigned int buf_len);

#include <errno.h>

#endif /* _IPMI_ERR_H */
