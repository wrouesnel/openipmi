# _control.py
#
# openipmi GUI handling for controls
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

class LightSet(wx.Dialog):
    def __init__(self, name, num_vals, light_list, vals, handler):
        self.handler = handler
        self.light_list = light_list
        wx.Dialog.__init__(self, None, -1, name, size=wx.Size(300, 300))

        sizer = wx.BoxSizer(wx.VERTICAL)
        
        self.values = scrolled.ScrolledPanel(self, -1,
                                             size=wx.Size(300, 200))
        self.lights = [ ]
        box = wx.BoxSizer(wx.VERTICAL)
        for i in range(0, num_vals):
            if (len(vals) <= i):
                ivals = ("", "black", '0', '1')
            else:
                ivals = vals[i]
                pass
            box2 = wx.BoxSizer(wx.HORIZONTAL)
            label = wx.StaticText(self.values, -1, "Light " + str(i))
            box2.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            if (light_list[i][0]):
                lc = wx.CheckBox(self.values, -1, "Local Control")
                lc.SetValue(ivals[0] == "lc")
                box2.Add(lc, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            else:
                lc = None
                pass
            box.Add(box2, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            color = wx.RadioBox(self.values, -1, "Color",
                                wx.DefaultPosition, wx.DefaultSize,
                                light_list[i][1], 2, wx.RA_SPECIFY_COLS)
            color.SetSelection(light_list[i][1].index(ivals[1]))
            box.Add(color, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            (b, ontime) = self.newField("On Time", self.values, ivals[2])
            box.Add(b, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            (b, offtime) = self.newField("Off Time", self.values, ivals[3])
            box.Add(b, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            self.lights.append((lc, color, ontime, offtime))
            pass
            
        self.values.SetSizer(box)
        sizer.Add(self.values, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(self, -1, "Cancel")
        wx.EVT_BUTTON(self, cancel.GetId(), self.cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(self, -1, "Ok")
        wx.EVT_BUTTON(self, ok.GetId(), self.ok_press);
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.SetSizer(sizer)
        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();
        self.Show(True);
        return

    def newField(self, name, parent, initval="", style=0):
        if parent == None:
            parent = self
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(parent, -1, name + ":")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        field = wx.TextCtrl(parent, -1, initval, style=style);
        box.Add(field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        return box, field;

    def cancel(self, event):
        self.Close()
        return

    def ok_press(self, event):
        val = [ ]
        try:
            i = 0;
            for f in self.lights:
                lc = ""
                if (f[0] != None) and f[0].GetValue():
                    lc = "lc"
                color = self.light_list[i][1][f[1].GetSelection()]
                ontime = str(f[2].GetValue())
                offtime = str(f[3].GetValue())
                val.append(' '.join([lc, color, ontime, offtime]))
                i = i + 1
                pass

            self.handler.ok(val)
            pass
        except Exception, e:
            print str(e)
            return
        self.Close()
        return

    def OnClose(self, event):
        self.Destroy()
        return

    pass
