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
import wx
import sys

id_st = 1300

class EventInfo:
    def __init__(self):
        self.sensor = None
        self.val = None

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

class SELDisplay(wx.Dialog):
    def __init__(self, o, type):
        self.o = o
        self.type = type
        self.numevents = 0
        wx.Dialog.__init__(self, None, -1, "SEL for " + o.get_name(),
                           size=wx.Size(500, 600),
                           style=wx.RESIZE_BORDER)

        sizer = wx.BoxSizer(wx.VERTICAL)

        self.listc = wx.ListCtrl(self, style=wx.LC_REPORT)
        listc = self.listc
        listc.InsertColumn(0, "RecNum")
        listc.InsertColumn(1, "Type")
        listc.InsertColumn(2, "Time/Sensor")
        listc.InsertColumn(3, "Data")
        
        sizer.Add(listc, 1, wx.GROW, 0)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        ok = wx.Button(self, -1, "Ok")
        wx.EVT_BUTTON(self, ok.GetId(), self.ok)
        box.Add(ok, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        clearall = wx.Button(self, -1, "Clear All")
        wx.EVT_BUTTON(self, clearall.GetId(), self.ClearAll)
        box.Add(clearall, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.evnum = 0
        self.events = { }
        
        ev = o.first_event()
        while (ev != None):
            self.AddEvent(ev)
            ev = o.next_event(ev)

        listc.SetColumnWidth(0, 65)
        listc.SetColumnWidth(1, 40)
        listc.SetColumnWidth(2, 200)
        listc.SetColumnWidth(3, 400)

        wx.EVT_LIST_ITEM_RIGHT_CLICK(self, -1, self.HandleMenu)

        self.SetSizer(sizer)
        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();
        self.Show(True)
        return

    def AddEvent(self, ev):
        listc = self.listc
        evinfo = EventInfo()
        ev.call_handler(evinfo)
        idx = listc.InsertStringItem(self.numevents, str(ev.get_record_id()))
        self.numevents += 1
        listc.SetStringItem(idx, 1, str(ev.get_type()))
        listc.SetStringItem(idx, 2, str(ev.get_timestamp()))
        listc.SetStringItem(idx, 3, str(ev.get_data()))
        self.events[self.evnum] = ev
        listc.SetItemData(idx, self.evnum)
        if (evinfo.sensor):
            idx = listc.InsertStringItem(self.numevents, "")
            self.numevents += 1
            listc.SetStringItem(idx, 2, evinfo.sensor)
            listc.SetStringItem(idx, 3, evinfo.val)
            listc.SetItemData(idx, self.evnum)
            pass
        self.evnum += 1
        
    def ok(self, event):
        self.Close()

    def ClearAll(self, event):
        items = self.events.items()
        for it in items:
            idx = it[0]
            ev = it[1]
            del self.events[idx]
            ev.delete()
        self.listc.ClearAll()
        self.numevents = 0

    def OnClose(self, event):
        self.Destroy()

    def HandleMenu(self, event):
        self.curr_idx = event.GetIndex()
        menu = wx.Menu();
        item = menu.Append(id_st+1, "Delete")
        wx.EVT_MENU(self, id_st+1, self.DelItem)

        rect = self.listc.GetItemRect(self.curr_idx)
        if (rect == None):
            point = None
        else:
            # FIXME - why do I have to subtract 25?
            point = wx.Point(rect.GetLeft(), rect.GetBottom()-25)
            pass
        self.PopupMenu(menu, point)
        menu.Destroy()

    def DelItem(self, event):
        key = self.listc.GetItemData(self.curr_idx)
        ev = self.events[key]
        del self.events[key]
        if (self.curr_idx > 0):
            key2 = self.listc.GetItemData(self.curr_idx - 1)
            if (key2 == key):
                self.listc.DeleteItem(self.curr_idx-1)
                self.numevents -= 1
                self.curr_idx -= 1
                pass
            pass
        if (self.curr_idx+1 < self.numevents):
            key2 = self.listc.GetItemData(self.curr_idx + 1)
            if (key2 == key):
                self.listc.DeleteItem(self.curr_idx+1)
                self.numevents -= 1
                pass
            pass
        self.listc.DeleteItem(self.curr_idx)
        self.numevents -= 1
        ev.delete()


class DomainSELDisplay(SELDisplay):
    def __init__(self, domain_id):
        self.domain_id = domain_id
        self.init = True
        domain_id.to_domain(self)

    def OnClose(self, event):
        self.init = False
        self.domain_id.to_domain(self)
        SELDisplay.OnClose(self, event)

    def domain_cb(self, domain):
        if (self.init):
            SELDisplay.__init__(self, domain, "domain")
            domain.add_event_handler(self)
        else:
            domain.remove_event_handler(self)

    def event_cb(self, domain, ev):
        self.AddEvent(ev)

class MCSELDisplay(SELDisplay):
    def __init__(self, mc_id):
        self.init = True
        self.mc_id = mc_id
        mc_id.to_mc(self)

    def OnClose(self, event):
        self.init = False
        self.mc_id.to_mc(self)
        SELDisplay.OnClose(self, event)

    def mc_cb(self, mc):
        domain = mc.get_domain()
        if self.init:
            SELDisplay.__init__(self, mc, "MC")
            domain.add_event_handler(self)
        else:
            domain.remove_event_handler(self)

    def event_cb(self, mc, ev):
        mc_id = ev.get_mc_id()
        if (mc_id.cmp(self.mc_id) == 0):
            self.AddEvent(ev)
