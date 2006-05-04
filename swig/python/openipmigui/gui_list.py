# gui_list.py
#
# openipmi GUI handling for a list
#
# Author: MontaVista Software, Inc.
#         Corey Minyard <minyard@mvista.com>
#         source@mvista.com
#
# Copyright 2006 MontaVista Software Inc.
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

import wx
import gui_errstr

class ListData:
    def __init__(self, key, data):
        self.key = key
        self.data = data
        return

    pass

class List(wx.Dialog):
    def __init__(self, name, columns):
        wx.Dialog.__init__(self, None, -1, name,
                           size=wx.Size(400, 600),
                           style=wx.RESIZE_BORDER)

        sizer = wx.BoxSizer(wx.VERTICAL)

        listc = wx.ListCtrl(self, style=wx.LC_REPORT)
        self.listc = listc
        
        i = 0
        for c in columns:
            listc.InsertColumn(i, c[0])
            listc.SetColumnWidth(i, c[1])
            i += 1
            pass
        
        sizer.Add(listc, 1, wx.GROW, 0)

        self.errstr = gui_errstr.ErrStr(self)
        sizer.Add(self.errstr, 0, wx.ALIGN_CENTRE | wx.ALL | wx.GROW, 5)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        if hasattr(self, "ok"):
            ok = wx.Button(self, -1, "Ok")
            wx.EVT_BUTTON(self, ok.GetId(), self.ok)
            box.Add(ok, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
            pass
        if hasattr(self, "save"):
            ok = wx.Button(self, -1, "Save")
            wx.EVT_BUTTON(self, ok.GetId(), self.save)
            box.Add(ok, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
            pass
        if hasattr(self, "cancel"):
            ok = wx.Button(self, -1, "Cancel")
            wx.EVT_BUTTON(self, ok.GetId(), self.cancel)
            box.Add(ok, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
            pass
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        wx.EVT_LIST_ITEM_RIGHT_CLICK(self.listc, -1, self.ListMenu)

        self.SetSizer(sizer)
        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();

        self.list_data = [ ]
        self.list_hash = { }
        self.currkey = 0

        return

    def AfterDone(self):
        self.Show(True)
        return

    def OnClose(self, event):
        if (hasattr(self, "do_on_close")):
            self.do_on_close()
            pass
        self.Destroy()
        return

    def ListMenu(self, event):
        idx = event.GetIndex()
        key = self.listc.GetItemData(idx)
        data = self.list_hash[key].data
        if (data and hasattr(data, "HandleMenu")):
            rect = self.listc.GetItemRect(idx)
            if (rect == None):
                point = None
            else:
                point = wx.Point(rect.GetLeft(), rect.GetBottom())
                pass
            data.HandleMenu(event, idx, point)
            pass
        return

    def DelItem(self, idx):
        key = self.listc.GetItemData(idx)
        self.listc.DeleteItem(idx)
        del self.list_hash[key]
        del self.list_data[idx]
        return

    def Append(self, name, values, data=None):
        idx = len(self.list_data)
        self.listc.InsertStringItem(idx, name)
        i = 1
        for v in values:
            if (v != None):
                self.listc.SetStringItem(idx, i, str(v))
            i += 1
            pass
        key = self.currkey;
        self.currkey += 1
        ldata = ListData(key, data)
        self.list_hash[key] = ldata
        self.list_data.append(key)
        self.listc.SetItemData(idx, key)
        return idx

    def SetColumn(self, idx, colnum, value):
        self.listc.SetStringItem(idx, colnum, value)
        return

    def SetError(self, str):
        self.errstr.SetError(str)
        return

    def add_data(self, name, values, data=None):
        idx = self.Append(name, values, data);
        if (data != None):
            data.SetItem(idx)
            pass
        return idx

    pass
