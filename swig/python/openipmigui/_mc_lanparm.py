# _mc_lanparm.py
#
# openipmi GUI handling for MC LAN parms
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

import sys
import OpenIPMI
import wx
import wx.gizmos as gizmos
import _oi_logging

id_st = 800

class MCLPData:
    def __init__(self, parm, idx, pname, ptype, origval):
        self.parm = parm
        self.idx = idx
        self.pname = pname
        self.ptype = ptype
        self.origval = origval
        self.currval = origval
        return

    pass

class MCValueSet(wx.Dialog):
    def __init__(self, mclp, idx, data):
        wx.Dialog.__init__(self, None, -1,
                           "Set value for " + data.pname,
                           size=wx.Size(300, 300),
                           style=wx.RESIZE_BORDER)
        self.mclp = mclp
        self.idx = idx
        self.data = data
    
        sizer = wx.BoxSizer(wx.VERTICAL)

        self.field = wx.TextCtrl(self, -1, data.currval)
        sizer.Add(self.field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)

        self.errstr = wx.StatusBar(self, -1)
        sizer.Add(self.errstr, 0, wx.ALIGN_CENTRE | wx.ALL, 5)

        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(self, -1, "Cancel")
        wx.EVT_BUTTON(self, cancel.GetId(), self.cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(self, -1, "Ok")
        wx.EVT_BUTTON(self, ok.GetId(), self.ok);
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.SetSizer(sizer)
        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();
        self.Show(True);
        return

    def OnClose(self, event):
        self.Destroy()
        return
    
    def cancel(self, event):
        self.Close()
        return

    def ok(self, event):
        val = str(self.field.GetValue())
        rv = self.mclp.lpc.set_val(self.data.parm, self.data.idx,
                                   self.data.ptype, val)
        if (rv != 0):
            self.errstr.SetStatusText("Invalid data value", 0)
            return
        self.data.currval = val
        self.mclp.listc.SetStringItem(self.idx, 1, val)
        self.Close()
        return

    pass
                 
class MCLanParm(wx.Dialog):
    def __init__(self, m, lp, lpc, channel):
        wx.Dialog.__init__(self, None, -1,
                           "LANPARMS for " + m.name + " channel "
                           + str(channel),
                           size=wx.Size(500, 600),
                           style=wx.RESIZE_BORDER)
        self.lp = lp
        self.lpc = lpc
        self.channel = channel
        
        sizer = wx.BoxSizer(wx.VERTICAL)

        self.listc = wx.ListCtrl(self, style=wx.LC_REPORT | wx.LC_EDIT_LABELS)
        listc = self.listc
        listc.InsertColumn(0, "Name")
        listc.InsertColumn(1, "Value")
        listc.SetColumnWidth(0, 200)
        listc.SetColumnWidth(1, 400)

        sizer.Add(listc, 1, wx.GROW, 0)

        self.errstr = wx.StatusBar(self, -1)
        sizer.Add(self.errstr, 0, wx.ALIGN_CENTRE | wx.ALL, 5)

        box = wx.BoxSizer(wx.HORIZONTAL)
        save = wx.Button(self, -1, "Save")
        wx.EVT_BUTTON(self, save.GetId(), self.save)
        box.Add(save, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        cancel = wx.Button(self, -1, "Cancel")
        wx.EVT_BUTTON(self, cancel.GetId(), self.cancel)
        box.Add(cancel, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        i = 0
        rv = True
        v = [ 0 ]
        itemdata = [ ]
        while (rv):
            lastv = v[0]
            rv = lpc.get_val(i, v)
            if (rv):
                vals = rv.split(" ", 2)
                if (len(vals) == 3):
                    # Valid parm
                    data = MCLPData(i, lastv, vals[0], vals[1], vals[2])
                    itemdata.append(data)
                    if (v[0] == 0):
                        item = listc.InsertStringItem(sys.maxint, vals[0])
                    else:
                        item = listc.InsertStringItem(sys.maxint,
                                                      vals[0] + "[" +
                                                      str(lastv) + "]")
                        pass
                    listc.SetStringItem(item, 1, vals[2])
                    listc.SetItemData(item, len(itemdata)-1)
                    if (v[0] == 0):
                        i += 1
                        pass
                    if (v[0] == -1):
                        i += 1
                        v[0] = 0
                        pass
                    pass
                else:
                    v[0] = 0
                    i += 1
                    pass
                pass
            pass

        self.itemdata = itemdata
        
        wx.EVT_LIST_ITEM_RIGHT_CLICK(self.listc, -1, self.ListMenu)

        self.SetSizer(sizer)
        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();
        self.Show(True)
        return

    def OnClose(self, event):
        if (self.lp):
            self.lp.clear_lock(self.lpc)
        self.Destroy();
        return

    def ListMenu(self, event):
        pos = event.GetIndex()
        self.current_position = pos
        idx = self.listc.GetItemData(self.current_position)
        data = self.itemdata[idx]

        rect = self.listc.GetItemRect(pos)
        if (rect == None):
            point = None
        else:
            # FIXME - why do I have to subtract 25?
            point = wx.Point(rect.GetLeft(), rect.GetBottom()-25)
            pass
                
        menu = wx.Menu()
        if (data.ptype == "bool"):
            item = menu.Append(id_st+1, "Toggle Value")
            wx.EVT_MENU(menu, id_st+1, self.togglevalue)
        else:
            item = menu.Append(id_st+2, "Set Value")
            wx.EVT_MENU(menu, id_st+2, self.setvalue)
            pass
        self.listc.PopupMenu(menu, point)
        menu.Destroy()
        return

    def setvalue(self, event):
        idx = self.listc.GetItemData(self.current_position)
        data = self.itemdata[idx]
        MCValueSet(self, idx, data)
        return

    def togglevalue(self, event):
        idx = self.listc.GetItemData(self.current_position)
        data = self.itemdata[idx]
        if (data.currval == "true"):
            newval = "false"
        else:
            newval = "true"
            pass
        rv = self.lpc.set_val(data.parm, data.idx,
                              data.ptype, newval)
        if (rv != 0):
            self.errstr.SetStatusText("Could not toggle value: "
                                      + OpenIPMI.get_error_string(rv), 0)
            return
            
        data.currval = newval
        self.listc.SetStringItem(self.current_position, 1, newval)
        return

    def save(self, event):
        rv = self.lp.set_config(self.lpc)
        if (rv != 0):
            self.errstr.SetStatusText("Error setting config: "
                                      + OpenIPMI.get_error_string(rv), 0)
            return

        # Don't forget to set self.lp to None when done so OnClose
        # doesn't clear it again
        self.lp = None
        self.Close()
        return

    def cancel(self, event):
        self.Close()
        return

    pass
