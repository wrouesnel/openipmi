/*
 * oem_intel.c
 *
 * OEM code to make Intel server systems work better.
 *
 *  (C) 2004 MontaVista Software, Inc.
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

#include <OpenIPMI/ipmi_oem.h>
#include <OpenIPMI/ipmi_addr.h>
#include <OpenIPMI/ipmi_mc.h>
#include <OpenIPMI/ipmi_domain.h>

#define INTEL_MANUFACTURER_ID 0x000157

static int
tsrlt2_handler(ipmi_mc_t     *mc,
	       void          *cb_data)
{
    ipmi_domain_t *domain = ipmi_mc_get_domain(mc);
    unsigned int  channel = ipmi_mc_get_channel(mc);
    unsigned int  addr    = ipmi_mc_get_address(mc);
    
    if ((channel == IPMI_BMC_CHANNEL) && (addr == IPMI_BMC_CHANNEL)) {
	/* It's the SI MC, which we detect at startup.  Set up the MCs
	   for the domain to scan. */
	ipmi_domain_add_ipmb_ignore_range(domain, 0x00, 0x1f);
	ipmi_domain_add_ipmb_ignore_range(domain, 0x21, 0x27);
	ipmi_domain_add_ipmb_ignore_range(domain, 0x29, 0xff);
    }

    return 0;
}


int
ipmi_oem_intel_init(void)
{
    int rv;

    rv = ipmi_register_oem_handler(INTEL_MANUFACTURER_ID,
				   0x000c,
				   tsrlt2_handler,
				   NULL,
				   NULL);
    if (rv)
	return rv;

    return 0;
}

void
ipmi_oem_intel_shutdown(void)
{
    ipmi_deregister_oem_handler(INTEL_MANUFACTURER_ID, 0x000c);
}
