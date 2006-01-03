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

class MCLPData:
    def __init__(self, parm, idx, ptype, origval):
        self.parm = parm
        self.idx = idx
        self.ptype = ptype
        self.origval = origval
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

        box = wx.BoxSizer(wx.HORIZONTAL)
        save = wx.Button(self, -1, "Save")
        self.Bind(wx.EVT_BUTTON, self.save, save);
        box.Add(save, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        cancel = wx.Button(self, -1, "Cancel")
        self.Bind(wx.EVT_BUTTON, self.cancel, cancel);
        box.Add(cancel, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        i = 0
        rv = "asdf"
        v = [ 0 ]
        itemdata = [ ]
        while (rv):
            lastv = v[0]
            rv = lpc.get_val(i, v)
            if (rv):
                vals = rv.split(" ", 2)
                if (len(vals) == 3):
                    # Valid parm
                    data = MCLPData(i, lastv, vals[1], vals[2])
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
        
        self.SetSizer(sizer)
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.Bind(wx.EVT_LIST_BEGIN_LABEL_EDIT, self.editlabel, listc)
        self.CenterOnScreen();
        self.Show(True)
        return

    def OnClose(self, event):
        if (self.lp):
            self.lp.clear_lock(self.lpc)
        self.Destroy();
        return

    def editlabel(self, event):
        print("Edit " + str(event.GetColumn()))
        if (event.GetColumn() == 0):
            event.Allow()
        else:
            event.Veto()
            pass
        return
    
    def save(self, event):
        # Don't forget to set self.lp to None when done so OnClose
        # doesn't clear it again
        return

    def cancel(self, event):
        self.Close()
        return

    pass
