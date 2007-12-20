# _sel.py
#
# openipmi GUI handling for SEL data
#
# Author: MontaVista Software, Inc.
#         Corey Minyard <minyard@mvista.com>
#         source@mvista.com
#
# Copyright 2005 MontaVista Software Inc.
#
#  This program is free software; you can redistribute it and/or
#  modify it under the terms of the GNU Lesser General Public License
#  as published by the Free Software Foundation; either version 2 of
#  the License, or (at your option) any later version.
#
#
#  THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
#  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
#  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
#  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
#  INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
#  BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS
#  OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
#  ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR
#  TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
#  USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#
#  You should have received a copy of the GNU Lesser General Public
#  License along with this program; if not, write to the Free
#  Software Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
#

import OpenIPMI
import sys
import gui_list
import gui_popup
import _misc

class EventData:
    def __init__(self, slist, ev, has_second_data):
        self.slist = slist
        self.ev = ev
        self.second_key = None
        return

    def HandleMenu(self, event, idx, point):
        gui_popup.popup(self.slist, event,
                        [ ("Delete", self.delete, idx) ],
                        point)
        return

    def delete(self, idx):
        self.slist.DelItem(self.key)
        if (self.second_key != None):
            self.slist.DelItem(self.second_key)
            pass
        self.ev.delete()
        return
    
    pass

class EventInfo:
    def __init__(self):
        self.sensor = None
        self.val = None
        return

    def threshold_event_cb(self, sensor, event_spec, raw_set, raw,
                           value_set, value, event):
        self.sensor = sensor.get_name()
        self.val = event_spec;
        if (value_set):
            self.val += str(value)
            pass
        if (raw_set):
            self.val += '(' + str(raw) + ')'
            pass
        return

    def discrete_event_cb(self, sensor, event_spec, severity, old_severity,
                          event):
        self.sensor = sensor.get_name()
        self.val = (event_spec + ' ' + str(severity) +
                    '(' + str(old_severity) + ')')
        return

    pass

class SELDisplay(gui_list.List):
    def __init__(self, o, type):
        self.o = o
        self.type = type
        self.numevents = 0
        gui_list.List.__init__(self, "SEL for " + o.get_name(),
                               [ ("RecNum", 64), ("Type", 40),
                                 ("Time/Sensor", 300), ("Data", 400) ])

        self.events = [ ]
        
        ev = o.first_event()
        while (ev != None):
            self.AddEvent(ev)
            ev = o.next_event(ev)
            pass

        self.AfterDone()
        return

    def AddEvent(self, ev):
        evinfo = EventInfo()
        ev.call_handler(evinfo)

        data = EventData(self, ev, evinfo.sensor != None)
        self.events.append(data)
        data.key = self.Append(str(ev.get_record_id()),
                               [ str(ev.get_type()), str(ev.get_timestamp()),
                                 _misc.HexArrayToStr(ev.get_data()) ],
                               data)
        if (evinfo.sensor):
            # Can only delete the using the first item.
            data.second_key = self.Append("", [ "", evinfo.sensor, evinfo.val ],
                                          data)
            pass
        return
        
    def ok(self):
        self.Close()
        return

    def clear(self):
        for data in self.events:
            data.ev.delete()
            pass
        self.events = [ ]
        self.DeleteAllItems()
        return

    def do_on_close(self):
        self.events = None
        return

    pass

class DomainSELDisplay(SELDisplay):
    def __init__(self, domain_id):
        self.domain_id = domain_id
        self.init = True
        domain_id.to_domain(self)
        return

    def do_on_close(self):
        self.init = False
        self.domain_id.to_domain(self)
        SELDisplay.do_on_close(self)
        return

    def domain_cb(self, domain):
        if (self.init):
            SELDisplay.__init__(self, domain, "domain")
            domain.add_event_handler(self)
        else:
            domain.remove_event_handler(self)
            pass
        return

    def event_cb(self, domain, ev):
        self.AddEvent(ev)
        return

    pass

class MCSELDisplay(SELDisplay):
    def __init__(self, mc_id):
        self.init = True
        self.mc_id = mc_id
        mc_id.to_mc(self)
        return

    def do_on_close(self):
        self.init = False
        self.mc_id.to_mc(self)
        SELDisplay.do_on_close(self)
        return
    
    def mc_cb(self, mc):
        domain = mc.get_domain()
        if self.init:
            SELDisplay.__init__(self, mc, "MC")
            domain.add_event_handler(self)
        else:
            domain.remove_event_handler(self)
            pass
        return

    def event_cb(self, domain, ev):
        mc_id = ev.get_mc_id()
        if (mc_id.cmp(self.mc_id) == 0):
            self.AddEvent(ev)
            pass
        return

    pass
