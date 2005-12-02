# _control.py
#
# openipmi GUI handling for controls
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
import wx.lib.scrolledpanel as scrolled

class ControlRefreshData:
    def __init__(self, c):
        self.c = c

    def control_cb(self, control):
        if (self.c.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            control.identifier_get_val(self.c)
        elif (self.c.setting_light):
            control.get_light(self.c)
        else:
            control.get_val(self.c)

class ControlSet:
    def __init__(self, c):
        self.c = c;

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(-1, "Modify Value")
        self.c.ui.Bind(wx.EVT_MENU, self.modval, item)
        self.c.ui.PopupMenu(menu, self.c.ui.get_item_pos(eitem))
        menu.Destroy()

    def modval(self, event):
        dialog = wx.Dialog(None, -1, "Set Control Values",
                           size=wx.Size(300, 300))
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)
        
        self.values = scrolled.ScrolledPanel(dialog, -1,
                                             size=wx.Size(300, 200))
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(self.values, -1, "Value(s):")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        box2 = wx.BoxSizer(wx.VERTICAL)
        self.fields = [ ]
        for i in range(0, self.c.num_vals):
            if (i >= len(self.c.vals)):
                v = '0'
            else:
                v = str(self.c.vals[i])
            field = wx.TextCtrl(self.values, -1, v)
            self.fields.append(field)
            box2.Add(field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        box.Add(box2, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        self.values.SetSizer(box)
        sizer.Add(self.values, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(dialog, -1, "Cancel")
        dialog.Bind(wx.EVT_BUTTON, self.cancel, cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(dialog, -1, "Ok")
        dialog.Bind(wx.EVT_BUTTON, self.ok, ok);
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        dialog.SetSizer(sizer)
        dialog.Bind(wx.EVT_CLOSE, self.OnClose)
        dialog.CenterOnScreen();
        dialog.Show(True);

    def cancel(self, event):
        self.dialog.Close()

    def ok(self, event):
        self.ival = [ ]
        try:
            for f in self.fields:
                val = f.GetValue()
                self.ival.append(int(val))
        except:
            return
        self.c.control_id.to_control(self)
        self.dialog.Close()

    def OnClose(self, event):
        self.dialog.Destroy()

    def control_cb(self, control):
        if (self.c.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            control.identifier_set_val(self.ival)
        else:
            control.set_val(self.ival)
        
class LightSet:
    def __init__(self, c):
        self.c = c;

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(-1, "Modify Value")
        self.c.ui.Bind(wx.EVT_MENU, self.modval, item)
        self.c.ui.PopupMenu(menu, self.c.ui.get_item_pos(eitem))
        menu.Destroy()

    def modval(self, event):
        dialog = wx.Dialog(None, -1, "Set Light Values",
                           size=wx.Size(300, 300))
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)
        
        self.values = scrolled.ScrolledPanel(dialog, -1,
                                             size=wx.Size(300, 200))
        self.lights = [ ]
        box = wx.BoxSizer(wx.VERTICAL)
        for i in range(0, self.c.num_vals):
            if (len(self.c.vals) <= i):
                ivals = ("", "black", '0', '1')
            else:
                ivals = self.c.vals[i]
            box2 = wx.BoxSizer(wx.HORIZONTAL)
            label = wx.StaticText(self.values, -1, "Light " + str(i))
            box2.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            if (self.c.lights[i][0]):
                lc = wx.CheckBox(self.values, -1, "Local Control")
                lc.SetValue(ivals[0] == "lc")
                box2.Add(lc, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            else:
                lc = None
            box.Add(box2, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            color = wx.RadioBox(self.values, -1, "Color",
                                wx.DefaultPosition, wx.DefaultSize,
                                self.c.lights[i][1], 2, wx.RA_SPECIFY_COLS)
            color.SetSelection(self.c.lights[i][1].index(ivals[1]))
            box.Add(color, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            (b, ontime) = self.newField("On Time", self.values, ivals[2])
            box.Add(b, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            (b, offtime) = self.newField("Off Time", self.values, ivals[3])
            box.Add(b, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
            self.lights.append((lc, color, ontime, offtime))
            
        self.values.SetSizer(box)
        sizer.Add(self.values, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(dialog, -1, "Cancel")
        dialog.Bind(wx.EVT_BUTTON, self.cancel, cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(dialog, -1, "Ok")
        dialog.Bind(wx.EVT_BUTTON, self.ok, ok);
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        dialog.SetSizer(sizer)
        dialog.Bind(wx.EVT_CLOSE, self.OnClose)
        dialog.CenterOnScreen();
        dialog.Show(True);

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
        self.dialog.Close()

    def ok(self, event):
        val = [ ]
        try:
            i = 0;
            for f in self.lights:
                lc = ""
                if (f[0] != None) and f[0].GetValue():
                    lc = "lc"
                color = self.c.lights[i][1][f[1].GetSelection()]
                ontime = str(f[2].GetValue())
                offtime = str(f[3].GetValue())
                val.append(' '.join([lc, color, ontime, offtime]))
                i = i + 1

            self.ival = ';'.join(val)
            self.c.control_id.to_control(self)
        except Exception, e:
            return
        self.dialog.Close()

    def OnClose(self, event):
        self.dialog.Destroy()

    def control_cb(self, control):
        rv = control.set_light(self.ival)
        if (rv != 0):
            raise ValueError("set_light failed: " + str(rv))
        
class Control:
    def __init__(self, e, control):
        self.e = e
        self.name = control.get_name()
        self.control_type_str = control.get_type_string()
        self.control_id = control.get_id()
        self.ui = e.ui;
        self.updater = ControlRefreshData(self)
        self.vals = [ ]
        self.ui.add_control(self.e, self)
        self.control_type = control.get_type()
        if (self.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            self.num_vals = control.identifier_get_max_length();
        else:
            self.num_vals = control.get_num_vals();

        if ((self.control_type == OpenIPMI.CONTROL_LIGHT)
            and (control.light_set_with_setting())):
            self.setting_light = True
            self.lights = [ ]
            for  i in range (0, self.num_vals):
                lc = control.light_has_local_control(i)
                colors = [ ]
                for j in range (0, OpenIPMI.CONTROL_NUM_COLORS):
                    if control.light_is_color_supported(i, j):
                        colors.append(OpenIPMI.color_string(j))
                self.lights.append((lc, colors))
        else:
            self.setting_light = False

        self.is_settable = control.is_settable()
        self.is_readable = control.is_readable()
        if (self.is_settable):
            if (self.setting_light):
                self.setter = LightSet(self)
            else:
                self.setter = ControlSet(self)
        else:
            self.setter = None

        self.ui.prepend_item(self, "Control Type", self.control_type_str)
        cs = [ ]
        if (control.has_events()):
            cs.append("generates_events")
        if (self.is_settable):
            cs.append("settable")
        if (self.is_readable):
            cs.append("readable")
        self.ui.append_item(self, "Control Capabilities", ' '.join(cs))
        if (self.control_type == OpenIPMI.CONTROL_LIGHT):
            self.ui.append_item(self, "Num Lights", str(self.num_vals))
            if (self.setting_light):
                self.ui.append_item(self, "Light Type", "setting")
                for i in range(0, self.num_vals):
                    cap = [ ]
                    if control.light_has_local_control(i):
                        cap.append("local_control")
                    for j in range (0, OpenIPMI.CONTROL_NUM_COLORS):
                        if control.light_is_color_supported(i, j):
                            cap.append(OpenIPMI.color_string(j))
                    self.ui.append_item(self, "Light" + str(i), ' '.join(cap))
            else:
                self.ui.append_item(self, "Light Type", "transition")
                for i in range(0, self.num_vals):
                    cap = [ ]
                    for j in range (0, control.get_num_light_values()):
                        cap2 = [ ]
                        for k in range (0,control.get_num_light_transitions()):
                            cap3 = [ ]
                            val = control.get_light_color(i, j, k)
                            cap3.append(OpenIPMI.color_string(val))
                            val = control.get_light_time(i, j, k)
                            cap3.append(OpenIPMI.color_string(cval))
                            cap2.append(cap3)
                        cap.append(cap2)
                    self.ui.append_item(self, "Light" + str(i), str(cap))
        elif (self.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            self.ui.append_item(self, "Max Length", str(self.num_vals))
        else:
            self.ui.append_item(self, "Num Vals", str(self.num_vals))

    def __str__(self):
        return self.name

    def DoUpdate(self):
        if (self.is_readable):
            self.control_id.to_control(self.updater)

    def HandleMenu(self, event):
        if (self.setter != None):
            self.setter.HandleMenu(event)
        
    def control_get_val_cb(self, control, err, vals):
        if (err != 0):
            self.ui.set_item_text(self.treeroot, None)
            return
        self.num_vals = control.get_num_vals();
        self.vals = vals
        self.ui.set_item_text(self.treeroot, str(vals))
        
    def control_get_id_cb(self, control, err, val):
        if (err != 0):
            self.ui.set_item_text(self.treeroot, None)
            return
        self.num_vals = control.identifier_get_max_length();
        self.val = val
        self.ui.set_item_text(self.treeroot, str(val))

    def control_get_light_cb(self, control, err, vals):
        if (err != 0):
            self.ui.set_item_text(self.treeroot, None)
            return
        self.num_vals = control.get_num_vals();
        v1 = vals.split(":")
        self.vals = [ ]
        for s1 in v1:
            v1 = s1.split()
            if (v1[0] != "lc"):
                v1.insert(0, "")
            self.vals.append(v1)
        self.ui.set_item_text(self.treeroot, str(self.vals))

    def remove(self):
        self.e.controls.pop(self.name)
        self.ui.remove_control(self)
