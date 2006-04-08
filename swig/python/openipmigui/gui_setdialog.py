# _domain.py
#
# openipmi GUI handling for a normal dialog
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
import wx.lib.scrolledpanel as scrolled

def isbool(v):
    return type(v) == type(True)

class SetDialog(wx.Dialog):
    def __init__(self, name, default, count, handler, labels=None):
        self.handler = handler
        wx.Dialog.__init__(self, None, -1, name)

        sizer = wx.BoxSizer(wx.VERTICAL)
        self.values = scrolled.ScrolledPanel(self, -1,
                                             size=wx.Size(300, 200))
        if (labels == None):
            box = wx.BoxSizer(wx.HORIZONTAL)
            if (count == 1):
                label = wx.StaticText(self.values, -1, "Value:")
            else:
                label = wx.StaticText(self.values, -1, "Value(s):")
                pass
            box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            box2 = wx.BoxSizer(wx.VERTICAL)
            self.fields = [ ]
            for i in range(0, count):
                if (isbool(default[i])):
                    field = wx.CheckBox(self.values, -1, "")
                else:
                    v = str(default[i])
                    field = wx.TextCtrl(self.values, -1, v)
                    pass
                self.fields.append(field)
                box2.Add(field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
                pass
            box.Add(box2, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            self.values.SetSizer(box)
            sizer.Add(self.values, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        else:
            box = wx.BoxSizer(wx.VERTICAL)
            self.fields = [ ]
            for i in range(0, count):
                box2 = wx.BoxSizer(wx.HORIZONTAL)
                if (isbool(default[i])):
                    field = wx.CheckBox(self.values, -1, labels[i])
                    field.SetValue(default[i])
                    pass
                else:
                    label = wx.StaticText(self.values, -1, labels[i])
                    box2.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
                    v = str(default[i])
                    field = wx.TextCtrl(self.values, -1, v)
                    pass
                self.fields.append(field)
                box2.Add(field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
                box.Add(box2, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
                pass
            pass
        self.values.SetupScrolling()
        self.values.SetSizer(box)
        sizer.Add(self.values, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(self, -1, "Cancel")
        wx.EVT_BUTTON(self, cancel.GetId(), self.cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(self, -1, "Ok")
        wx.EVT_BUTTON(self, ok.GetId(), self.ok);
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        # FIXME - add error string.

        self.SetSizer(sizer)
        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();
        self.Show(True);
        return
    
    def cancel(self, event):
        self.Close()
        return

    def ok(self, event):
        vals = [ ]
        for f in self.fields:
            vals.append(f.GetValue())
            pass
        try:
            self.handler.ok(vals)
        except:
            return
        self.Close()
        return

    def OnClose(self, event):
        self.Destroy()
        return

    pass
