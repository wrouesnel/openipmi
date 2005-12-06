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
import logging
import wx
import sys

class SELDisplay(wx.Dialog):
    def __init__(self, o, type):
        self.o = o
        self.type = type
        wx.Dialog.__init__(self, None, -1, "SEL for " + o.get_name(),
                           size=wx.Size(400, 600),
                           style=wx.RESIZE_BORDER)

        sizer = wx.BoxSizer(wx.VERTICAL)

        self.listc = wx.ListCtrl(self, style=wx.LC_REPORT)
        listc = self.listc
        listc.InsertColumn(0, "RecNum")
        listc.InsertColumn(1, "Type")
        listc.InsertColumn(2, "Time")
        listc.InsertColumn(3, "Data")
        
        sizer.Add(listc, 1, wx.GROW, 0)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        ok = wx.Button(self, -1, "Ok")
        self.Bind(wx.EVT_BUTTON, self.ok, ok);
        box.Add(ok, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        clearall = wx.Button(self, -1, "Clear All")
        self.Bind(wx.EVT_BUTTON, self.ClearAll, clearall);
        box.Add(clearall, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.evnum = 0
        self.events = { }
        
        ev = o.first_event()
        while (ev != None):
            idx = listc.InsertStringItem(sys.maxint, str(ev.get_record_id()))
            listc.SetStringItem(idx, 1, str(ev.get_type()))
            listc.SetStringItem(idx, 2, str(ev.get_timestamp()))
            listc.SetStringItem(idx, 3, str(ev.get_data()))
            self.events[self.evnum] = ev
            listc.SetItemData(idx, self.evnum)
            self.evnum += 1
            ev = o.next_event(ev)

        listc.SetColumnWidth(0, 65)
        listc.SetColumnWidth(1, 40)
        listc.SetColumnWidth(2, 120)
        listc.SetColumnWidth(3, 400)

        self.Bind(wx.EVT_LIST_ITEM_RIGHT_CLICK, self.HandleMenu)

        self.SetSizer(sizer)
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.CenterOnScreen();
        self.Show(True)

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

    def OnClose(self, event):
        self.Destroy()

    def HandleMenu(self, event):
        self.curr_idx = event.GetIndex()
        menu = wx.Menu();
        item = menu.Append(-1, "Delete")
        self.Bind(wx.EVT_MENU, self.DelItem, item)

        rect = self.listc.GetItemRect(self.curr_idx)
        if (rect == None):
            return None
        (x, y) = event.GetPosition().Get()
        pos = wx.Point(x, rect.GetBottom())

        self.PopupMenu(menu, pos)
        menu.Destroy()

    def DelItem(self, event):
        key = self.listc.GetItemData(self.curr_idx)
        ev = self.events[key]
        del self.events[key]
        self.listc.DeleteItem(self.curr_idx)
        ev.delete()


class DomainSELDisplay(SELDisplay):
    def __init__(self, domain_id):
        domain_id.to_domain(self)

    def OnClose(self, event):
        self.Destroy()
        SELDisplay.OnClose(self, event)

    def domain_cb(self, domain):
        SELDisplay.__init__(self, domain, "domain")
        domain.add_event_handler(self)

    def event_cb(self, domain, ev):
        idx = self.listc.InsertStringItem(sys.maxint, str(ev.get_record_id()))
        self.listc.SetStringItem(idx, 1, str(ev.get_type()))
        self.listc.SetStringItem(idx, 2, str(ev.get_timestamp()))
        self.listc.SetStringItem(idx, 3, str(ev.get_data()))
        self.events[self.evnum] = ev
        self.listc.SetItemData(idx, self.evnum)
        self.evnum += 1
