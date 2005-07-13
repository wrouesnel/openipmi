/*
 * ipmi_utils.c
 *
 * MontaVista IPMI generic utilities
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

#include <errno.h>

#include <OpenIPMI/internal/ipmi_int.h>

unsigned int ipmi_get_uint32(const unsigned char *data)
{
    return (data[0]
	    | (data[1] << 8)
	    | (data[2] << 16)
	    | (data[3] << 24));
}

/* Extract a 16-bit integer from the data, IPMI (little-endian) style. */
unsigned int ipmi_get_uint16(const unsigned char *data)
{
    return (data[0]
	    | (data[1] << 8));
}

/* Add a 32-bit integer to the data, IPMI (little-endian) style. */
void ipmi_set_uint32(unsigned char *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
    data[2] = (val >> 16) & 0xff;
    data[3] = (val >> 24) & 0xff;
}

/* Add a 16-bit integer to the data, IPMI (little-endian) style. */
void ipmi_set_uint16(unsigned char *data, int val)
{
    data[0] = val & 0xff;
    data[1] = (val >> 8) & 0xff;
}

int
ipmi_addr_equal(const ipmi_addr_t *addr1,
		int               addr1_len,
		const ipmi_addr_t *addr2,
		int               addr2_len)
{
    if (addr1_len != addr2_len)
	return 0;

    if (addr1->addr_type != addr2->addr_type)
	return 0;

    if (addr1->channel != addr2->channel)
	return 0;

    switch (addr1->addr_type)
    {
	case IPMI_IPMB_ADDR_TYPE:
	{
	    ipmi_ipmb_addr_t *iaddr1 = (ipmi_ipmb_addr_t *) addr1;
	    ipmi_ipmb_addr_t *iaddr2 = (ipmi_ipmb_addr_t *) addr2;

	    return ((iaddr1->slave_addr == iaddr2->slave_addr)
		    && (iaddr1->lun == iaddr2->lun));
	}

	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	{
	    ipmi_system_interface_addr_t *iaddr1
		= (ipmi_system_interface_addr_t *) addr1;
	    ipmi_system_interface_addr_t *iaddr2
		= (ipmi_system_interface_addr_t *) addr2;
	    return (iaddr1->lun == iaddr2->lun);
	}

	if (addr1->addr_type == IPMI_LAN_ADDR_TYPE) {
		struct ipmi_lan_addr *lan_addr1
			= (struct ipmi_lan_addr *) addr1;
		struct ipmi_lan_addr *lan_addr2
		    = (struct ipmi_lan_addr *) addr2;

		return ((lan_addr1->remote_SWID == lan_addr2->remote_SWID)
			&& (lan_addr1->local_SWID == lan_addr2->local_SWID)
			&& (lan_addr1->privilege == lan_addr2->privilege)
			&& (lan_addr1->session_handle
			    == lan_addr2->session_handle)
			&& (lan_addr1->lun == lan_addr2->lun));
	}

	default:
	    return 0;
    }
}

int
ipmi_addr_equal_nolun(const ipmi_addr_t *addr1,
		      int               addr1_len,
		      const ipmi_addr_t *addr2,
		      int               addr2_len)
{
    if (addr1_len != addr2_len)
	return 0;

    if (addr1->addr_type != addr2->addr_type)
	return 0;

    if (addr1->channel != addr2->channel)
	return 0;

    /* Note that we do *not* include the LUN in address comparisons. */
    switch (addr1->addr_type)
    {
	case IPMI_IPMB_ADDR_TYPE:
	{
	    ipmi_ipmb_addr_t *iaddr1 = (ipmi_ipmb_addr_t *) addr1;
	    ipmi_ipmb_addr_t *iaddr2 = (ipmi_ipmb_addr_t *) addr2;

	    return (iaddr1->slave_addr == iaddr2->slave_addr);
	}

	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	    return 1;

	if (addr1->addr_type == IPMI_LAN_ADDR_TYPE) {
		struct ipmi_lan_addr *lan_addr1
			= (struct ipmi_lan_addr *) addr1;
		struct ipmi_lan_addr *lan_addr2
		    = (struct ipmi_lan_addr *) addr2;

		return ((lan_addr1->remote_SWID == lan_addr2->remote_SWID)
			&& (lan_addr1->local_SWID == lan_addr2->local_SWID)
			&& (lan_addr1->privilege == lan_addr2->privilege)
			&& (lan_addr1->session_handle
			    == lan_addr2->session_handle));
	}

	default:
	    return 0;
    }
}

unsigned int
ipmi_addr_get_lun(const ipmi_addr_t *addr)
{
    switch (addr->addr_type)
    {
	case IPMI_IPMB_ADDR_TYPE:
	{
	    ipmi_ipmb_addr_t *iaddr = (ipmi_ipmb_addr_t *) addr;

	    return iaddr->lun;
	}

	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	{
	    ipmi_system_interface_addr_t *iaddr
		= (ipmi_system_interface_addr_t *) addr;

	    return iaddr->lun;
	}

	case IPMI_LAN_ADDR_TYPE:
	{
	    struct ipmi_lan_addr *iaddr
		= (struct ipmi_lan_addr *) addr;

	    return iaddr->lun;
	}

	default:
	    return 0;
    }
}

int
ipmi_addr_set_lun(ipmi_addr_t *addr, unsigned int lun)
{
    if (lun >= 4)
	return EINVAL;

    switch (addr->addr_type)
    {
	case IPMI_IPMB_ADDR_TYPE:
	{
	    ipmi_ipmb_addr_t *iaddr = (ipmi_ipmb_addr_t *) addr;

	    iaddr->lun = lun;
	    break;
	}

	case IPMI_SYSTEM_INTERFACE_ADDR_TYPE:
	{
	    ipmi_system_interface_addr_t *iaddr
		= (ipmi_system_interface_addr_t *) addr;

	    iaddr->lun = lun;
	    break;
	}

	case IPMI_LAN_ADDR_TYPE:
	{
	    struct ipmi_lan_addr *iaddr
		= (struct ipmi_lan_addr *) addr;

	    iaddr->lun = lun;
	    break;
	}

	default:
	    return EINVAL;
    }

    return 0;
}

/* Returns 0 if the address doesn't have a slave address. */
unsigned int
ipmi_addr_get_slave_addr(const ipmi_addr_t *addr)
{
    switch (addr->addr_type)
    {
	case IPMI_IPMB_ADDR_TYPE:
	{
	    ipmi_ipmb_addr_t *iaddr = (ipmi_ipmb_addr_t *) addr;

	    return iaddr->slave_addr;
	}

	default:
	    return 0;
    }
}


