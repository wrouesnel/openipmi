/*
 * cmdlang.c
 *
 * A command interpreter for OpenIPMI
 *
 * Author: MontaVista Software, Inc.
 *         Corey Minyard <minyard@mvista.com>
 *         source@mvista.com
 *
 * Copyright 2004 MontaVista Software Inc.
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

#include <OpenIPMI/ipmiif.h>

typedef struct cmd_info_s cmd_info_t;
typedef int (*cmd_out_cb)(cmd_info_t *info, char *output);
typedef int (*cmd_done_cb)(cmd_info_t *info);

typedef int (*objparse_handler_cb)(int argc, char *argv[]);


struct cmd_info_s
{
    cmd_info_t          *info;
    char                *str;
    int                 strstart, strlen;

    char                *working_str;

    int                 argc;
    char                *argv[];
    objparse_handler_cb handler;
    unsigned int        level;

    cmd_out_cb  out;
    cmd_done_cb done;
};

static int for_each_domain(cmd_info_t         *info,
			   ipmi_domain_ptr_cb handler)
{
    if (info->strlen == 0) {
	info->working_str = NULL;
    } else {
	info->working_str = strndup(info->str + info->strstart, info->strlen);
	if (!info->working_str)
	    return ENOMEM;
    }

    ipmi_domain_iterate_domains(handler, info);
}

static int for_each_entity(cmd_info_t         *info,
			   ipmi_entity_ptr_cb handler)
{
    int  i;
    char *str = info->str + info->strstart;

    for (i=0, i<info->strlen; i++) {
	
    }
}

static int for_each_sensor(cmd_info_t *info, char *str,
			   int argc, char *argv[],
			   objparse_handler handler)
{
    
}

static int for_each_control(cmd_info_t *info, char *str,
			    int argc, char *argv[],
			    objparse_handler handler)
{
    
}

static int for_each_mc(cmd_info_t *info, char *str,
		       int argc, char *argv[],
		       objparse_handler handler)
{
    
}

static int for_each_connection(cmd_info_t *info, char *str,
			       int argc, char *argv[],
			       objparse_handler handler)
{
    
}

The command hierarchy is:

* help - get general help.
* domain
  * help
  * list - List all domains
  * info <domain> - List information about the given domain
  * fru <is_logical> <device_address> <device_id> <lun> <private_bus>
    <channel> - dump a fru given all it's insundry information.
  * msg <mc> <LUN> <NetFN> <Cmd> [data...] - Send a command
    to the given IPMB address on the given channel and display the
    response.  Note that this does not require the existance of an
    MC.
  * pet <connection> <channel> <ip addr> <mac_addr> <eft selector>
    <policy num> <apt selector> <lan dest selector> - 
    Set up the domain to send PET traps from the given connection
    to the given IP/MAC address over the given channel
  * scan <ipmb addr> [ipmb addr] - scan an IPMB to add or remove it.
    If a range is given, then scan all IPMBs in the range
  * presence - Check the presence of entities
  new <domain> <parms...> - Open a connection to a new domain
  close <domain> - close the given domain
* entity
  * help
  * list <domain> - List all entities.
  * info <entity> - List information about the given entity
  * hs - hot-swap control
    * get_act_time <entity> - Get the host-swap auto-activate time
    * set_act_time <entity> - Set the host-swap auto-activate time
    * get_deact_time <entity> - Get the host-swap auto-deactivate time
    * set_deact_time <entity> - Set the host-swap auto-deactivate time
    * activation_request <entity> Act like a user requested an
      activation of the entity.  This is generally equivalent to
      closing the handle latch or something like that.
    * activate <entity> - activate the given entity
    * deactivate <entity> - deactivate the given entity
    * state <entity> - Return the current hot-swap state of the given entity
    * check <domain> - Audit all the entity hot-swap states
  * fru <entity> - Dump the FRU information about the given entity.
* sensor
  * help
  * list <entity> - List all sensors
  * info <sensor> 
  * rearm <sensor> - rearm the current sensor
  * set_hysteresis - Sets the hysteresis for the current sensor
  * get_hysteresis - Gets the hysteresis for the current sensor
  * events_enable <events> <scanning> <assertion bitmask> <deassertion bitmask>
    - set the events enable data for the sensor
* control
  * help
  * list <entity> - List all controls
  * info <control> 
  * set <control> <val1> [<val2> ...] - set the value(s) for the control
* mc
  * help
  * list <domain> - List all MCs
  * info <mc> 
  * reset <warm | cold> <mc> - Do a warm or cold reset on the given MC
  * cmd <mc> <LUN> <NetFN> <Cmd> [data...] - Send the given command"
    to the management controller and display the response.
  * set_events_enable <enable | disable> <mc> - enables or disables
    events on the MC.
  * get_events_enabled <mc> - Prints out if the events are enabled for
    the given MC.
  * sdrs <main | sensor> <mc> - list the SDRs for the mc.  Either gets
    the main SDR repository or the sensor SDR repository.
  * get_sel_time <mc> - Get the time in the SEL for the given MC
* pef
  * read <mc> - read pef information from an MC.  Note the lock is not
    released.
  * clearlock <mc> - Clear a PEF lock.
  * write <mc> <pefval> <value> [pefval <value> [...]]
    - write the PEF information to the MC.  Every value given will be
     written atomically and the lock will be released.  Note that
     you must do a read before doing this command.
* lan
    * read <mc> <channel> - read lanparm information from an MC for
      the given channel on the MC.  Note the lock will not be released
      after this command.
    * clearlock <mc> <channel> - Clear the LAN parm lock on the given
      MC and channel.
    * writelanparm <mc> <channel> <lanval> <value> [lanval <value> [...]]
      - write the LANPARM information to an MC.  Every value given will be
      written atomically and the lock will be released.  Note that
      you must do a read before doing this command.
* con
  * active <connection> - print out if the given connection is active or not
  * activate <connection> - Activate the given connection
* sel
    * delevent <mc> <log #> - Delete the given event number from the SEL
    * addevent <mc> <record id> <type> <13 bytes of data> - Add the
      event data to the SEL.
    * clear <domain> - clear the system event log
    * list <domain> - list the local copy of the system event log
* general
  * debug <type> on|off - Turn the given debugging type on or off
  * xml on|off - enable or disable XML-style output
