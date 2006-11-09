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
import gui_popup
import gui_setdialog
import gui_lightset

class ControlRefreshData:
    def __init__(self, c):
        self.c = c
        return

    def control_cb(self, control):
        if (self.c.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            control.identifier_get_val(self.c)
        elif (self.c.setting_light):
            control.get_light(self.c)
        else:
            control.get_val(self.c)
            pass
        return
    
    pass

class ControlSet:
    def __init__(self, c):
        self.c = c;
        return

    def HandleMenu(self, event):
        if (self.c.impt_data == None):
            ml = [ [ "Add to watch values", self.c.add_impt ] ]
            pass
        else:
            ml = [ [ "Remove from watch values", self.c.remove_impt ] ]
            pass
        ml.append([ "Modify Value", self.modval ])
        ml.append([ "Set to 0",     self.SetTo0 ])
        ml.append([ "Set to 1",     self.SetTo1 ])
        gui_popup.popup(self.c.ui, event, ml)
        return

    def modval(self, event):
        vals = self.c.vals
        while (len(vals) < self.c.num_vals):
            vals.append(0)
            pass
        gui_setdialog.SetDialog("Set Control Values for " + self.c.name,
                                vals,
                                self.c.num_vals,
                                self)
        return

    def SetTo0(self, event):
        self.ival = [ 0 ]
        self.c.control_id.to_control(self)
        return

    def SetTo1(self, event):
        self.ival = [ 1 ]
        self.c.control_id.to_control(self)
        return

    def ok(self, vals):
        self.ival = [ ]
        for val in vals:
            self.ival.append(int(val))
            pass
        self.c.control_id.to_control(self)
        return

    def control_cb(self, control):
        if (self.c.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            control.identifier_set_val(self.ival)
        else:
            control.set_val(self.ival)
            pass
        return

    def do_on_close(self):
        self.c = None

    pass
        
class LightSet:
    def __init__(self, c):
        self.c = c;
        return

    def HandleMenu(self, event):
        if (self.c.impt_data == None):
            ml = [ [ "Add to watch values", self.c.add_impt ] ]
            pass
        else:
            ml = [ [ "Remove from watch values", self.c.remove_impt ] ]
            pass
        ml.append([ "Modify Value", self.modval ])
        gui_popup.popup(self.c.ui, event, ml)
        return

    def modval(self, event):
        gui_lightset.LightSet("Set Light Values for " + self.c.name,
                              self.c.num_vals, self.c.lights, self.c.vals,
                              self);
        return

    def ok(self, val):
        self.ival = ';'.join(val)
        self.c.control_id.to_control(self)
        return

    def control_cb(self, control):
        rv = control.set_light(self.ival)
        if (rv != 0):
            raise ValueError("set_light failed: " + str(rv))
        return
        
class Control:
    def __init__(self, e, control):
        self.e = e
        self.name = control.get_name()
        e.controls[self.name] = self
        self.control_type_str = control.get_type_string()
        self.control_id = control.get_id()
        self.ui = e.ui;
        self.updater = ControlRefreshData(self)
        self.vals = [ ]
        self.ui.add_control(self.e, self)
        self.control_type = control.get_type()
        self.destroyed = False
        if (self.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            self.num_vals = control.identifier_get_max_length();
        else:
            self.num_vals = control.get_num_vals();
            pass

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
                        pass
                    pass
                self.lights.append((lc, colors))
                pass
            pass
        else:
            self.setting_light = False
            pass

        self.is_settable = control.is_settable()
        self.is_readable = control.is_readable()
        if (self.is_settable):
            if (self.setting_light):
                self.setter = LightSet(self)
            else:
                self.setter = ControlSet(self)
                pass
            pass
        else:
            self.setter = None
            pass

        self.ui.prepend_item(self, "Control Type", self.control_type_str)
        cs = [ ]
        if (control.has_events()):
            cs.append("generates_events")
            pass
        if (self.is_settable):
            cs.append("settable")
            pass
        if (self.is_readable):
            cs.append("readable")
            pass
        self.ui.append_item(self, "Control Capabilities", ' '.join(cs))
        if (self.control_type == OpenIPMI.CONTROL_LIGHT):
            self.ui.append_item(self, "Num Lights", str(self.num_vals))
            if (self.setting_light):
                self.ui.append_item(self, "Light Type", "setting")
                for i in range(0, self.num_vals):
                    cap = [ ]
                    if control.light_has_local_control(i):
                        cap.append("local_control")
                        pass
                    for j in range (0, OpenIPMI.CONTROL_NUM_COLORS):
                        if control.light_is_color_supported(i, j):
                            cap.append(OpenIPMI.color_string(j))
                            pass
                        pass
                    self.ui.append_item(self, "Light" + str(i), ' '.join(cap))
                    pass
                pass
            else:
                self.ui.append_item(self, "Light Type", "transition")
                for i in range(0, self.num_vals):
                    cap = [ ]
                    for j in range (0, control.get_num_light_values(i)):
                        cap2 = [ ]
                        for k in range (0,control.get_num_light_transitions(i, j)):
                            cap3 = [ ]
                            val = control.get_light_color(i, j, k)
                            cap3.append(OpenIPMI.color_string(val))
                            val = control.get_light_color_time(i, j, k)
                            cap3.append(OpenIPMI.color_string(val))
                            cap2.append(cap3)
                            pass
                        cap.append(cap2)
                        pass
                    self.ui.append_item(self, "Light" + str(i), str(cap))
                    pass
                pass
            pass
        elif (self.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            self.ui.append_item(self, "Max Length", str(self.num_vals))
        else:
            self.ui.append_item(self, "Num Vals", str(self.num_vals))
            pass
        return
    
    def __str__(self):
        return self.name

    def DoUpdate(self):
        if (self.is_readable):
            self.control_id.to_control(self.updater)
            pass
        return

    def HandleMenu(self, event):
        if (self.setter != None):
            self.setter.HandleMenu(event)
            pass
        else:
            if (self.impt_data == None):
                ml = [ [ "Add to watch values", self.add_impt ] ]
                pass
            else:
                ml = [ [ "Remove from watch values", self.remove_impt ] ]
                pass
            gui_popup.popup(self.ui, event, ml)
            pass
        return

    def add_impt(self, event):
        self.ui.add_impt_data("control", str(self), self)
        return
        
    def remove_impt(self, event):
        self.ui.remove_impt_data(self.impt_data)
        return
        
    def control_get_val_cb(self, control, err, vals):
        if (self.destroyed):
            return
        if (err != 0):
            self.ui.set_item_text(self.treeroot, None)
            return
        self.num_vals = control.get_num_vals();
        self.vals = vals
        self.ui.set_item_text(self.treeroot, str(vals))
        return
        
    def control_get_id_cb(self, control, err, val):
        if (self.destroyed):
            return
        if (err != 0):
            self.ui.set_item_text(self.treeroot, None)
            return
        self.num_vals = control.identifier_get_max_length();
        self.val = val
        self.ui.set_item_text(self.treeroot, str(val))
        return

    def control_get_light_cb(self, control, err, vals):
        if (self.destroyed):
            return
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
                pass
            self.vals.append(v1)
            pass
        self.ui.set_item_text(self.treeroot, str(self.vals))
        return

    def remove(self):
        self.e.controls.pop(self.name)
        self.ui.remove_control(self)
        self.destroyed = True
        self.e = None
        self.updater = None
        self.ui = None
        return

    pass
