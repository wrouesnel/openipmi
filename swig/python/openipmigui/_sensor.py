# _sensor.py
#
# openipmi GUI handling for sensors
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
import wx
import wx.lib.scrolledpanel as scrolled
import OpenIPMI
import _oi_logging

id_st = 700

class SensorRefreshData:
    def __init__(self, s):
        self.s = s

    def sensor_cb(self, sensor):
        sensor.get_value(self.s)


class SensorInfoGetter:
    def __init__(self, s, func):
        self.s = s;
        self.func = func;

    def DoUpdate(self):
        self.s.sensor_id.to_sensor(self)

    def sensor_cb(self, sensor):
        getattr(sensor, self.func)(self.s)


threshold_strings = [ 'ur', 'uc', 'un', 'ln', 'lc', 'lr' ]
threshold_full_strings = [ 'upper non-recoverable',
                           'upper critical',
                           'upper non-critical',
                           'lower non-critical',
                           'lower critical',
                           'lower non-recoverable' ]

def threshold_str_to_full(s):
    i = threshold_strings.index(s)
    return threshold_full_strings[i]

threshold_event_strings = [ 'urha', 'urhd', 'urla', 'urld',
                            'ucha', 'uchd', 'ucla', 'ucld',
                            'unha', 'unhd', 'unla', 'unld',
                            'lnha', 'lnhd', 'lnla', 'lnld',
                            'lcha', 'lchd', 'lcla', 'lcld',
                            'lrha', 'lrhd', 'lrla', 'lrld' ]

def threshold_event_str_to_full(s):
    rv = threshold_str_to_full(s[0:2])
    if (s[2] == 'h'):
        rv += " going high"
    else:
        rv += " going low"
    if (s[3] == 'a'):
        rv += " assertion"
    else:
        rv += " deassertion"
    return rv

def discrete_event_str_to_full(s, name):
    l = len(s)
    num = int(s[0:l-1])
    t = s[l-1:l]
    if (t == 'a'):
        t = 'assertion'
    else:
        t = 'deassertion'
    return s[0:l-1] + ' ' + t + ' (' + name + ')'

class SensorHysteresisSet(wx.Dialog):
    def __init__(self, s):
        wx.Dialog.__init__(self, None, -1, "Set Hysteresis for " + str(s))
        self.s = s
        sizer = wx.BoxSizer(wx.VERTICAL)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(self, -1, "Positive:")
        box.Add(label, 0, wx.ALIGN_LEFT | wx.ALL, 5)
        self.pos = wx.TextCtrl(self, -1, "")
        box.Add(self.pos, 0, wx.ALIGN_LEFT | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 2)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(self, -1, "Negative:")
        box.Add(label, 0, wx.ALIGN_LEFT | wx.ALL, 5)
        self.neg = wx.TextCtrl(self, -1, "")
        box.Add(self.neg, 0, wx.ALIGN_LEFT | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 2)

        box = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(self, -1, "Cancel")
        wx.EVT_BUTTON(self, cancel.GetId(), self.cancel)
        box.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(self, -1, "Ok")
        wx.EVT_BUTTON(self, ok.GetId(), self.ok)
        box.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.SetSizer(sizer)
        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();
        self.setting = False
        if (s.sensor_id.to_sensor(self) != 0):
            self.Destroy()

    def cancel(self, event):
        self.Close()

    def ok(self, event):
        try:
            self.positive = int(self.pos.GetValue())
        except:
            return
        try:
            self.negative = int(self.neg.GetValue())
        except:
            return
        rv = self.s.sensor_id.to_sensor(self)
        if (rv == 0):
            rv = self.err
        if (rv != 0):
            _oi_logging.error("Error setting sensor thresholds: " + str(rv))
            self.Close()

    def OnClose(self, event):
        self.Destroy()

    def sensor_cb(self, sensor):
        if (self.setting):
            self.err = sensor.set_hysteresis(self.positive, self.negative, self)
        else:
            sensor.get_hysteresis(self)
            self.setting = True

    def sensor_get_hysteresis_cb(self, sensor, err, positive, negative):
        if (err != 0):
            _oi_logging.error("Error getting sensor hysteresis: " + str(err))
            self.Destroy()
        else:
            self.pos.SetValue(str(positive))
            self.neg.SetValue(str(negative))
            self.Show(True);

    def sensor_set_hysteresis_cb(self, sensor, err):
        if (err):
            _oi_logging.error("Unable to set sensor thresholds: " + str(err))
        else:
            sensor.get_hysteresis(self.s)
        self.Close()


class SensorThresholdsSet(wx.Dialog):
    def __init__(self, s):
        wx.Dialog.__init__(self, None, -1, "Set Thresholds for " + str(s))
        self.s = s
        sizer = wx.BoxSizer(wx.VERTICAL)

        self.thresholds = { }
        for th in s.settable_thresholds.split():
            box = wx.BoxSizer(wx.HORIZONTAL)
            label = wx.StaticText(self, -1, threshold_str_to_full(th))
            box.Add(label, 0, wx.ALIGN_LEFT | wx.ALL, 5)
            th_text_box = wx.TextCtrl(self, -1, "")
            self.thresholds[th] = th_text_box
            box.Add(th_text_box, 0, wx.ALIGN_LEFT | wx.ALL, 5)
            sizer.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 2)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(self, -1, "Cancel")
        wx.EVT_BUTTON(self, cancel.GetId(), self.cancel)
        box.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(self, -1, "Ok")
        wx.EVT_BUTTON(self, ok.GetId(), self.ok)
        box.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.SetSizer(sizer)
        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();

        self.setting = False
        if (s.sensor_id.to_sensor(self) != 0):
            self.Destroy()

    def cancel(self, event):
        self.Close()

    def ok(self, event):
        tlist = [ ]
        for ths in self.thresholds.iteritems():
            try:
                tlist.append(ths[0] + " " + str(float(ths[1].GetValue())))
            except:
                return
        self.threshold_str = ":".join(tlist)
        rv = self.s.sensor_id.to_sensor(self)
        if (rv == 0):
            rv = self.err
        if (rv != 0):
            _oi_logging.error("Error setting sensor thresholds: " + str(rv))
            self.Close()

    def OnClose(self, event):
        self.Destroy()

    def sensor_cb(self, sensor):
        if (self.setting):
            self.err = sensor.set_thresholds(self.threshold_str, self)
        else:
            rv = sensor.get_thresholds(self)
            if (rv != 0):
                _oi_logging.error("Error getting sensor thresholds: " + str(rv))
                self.Destroy()
                return
            self.setting = True

    def sensor_get_thresholds_cb(self, sensor, err, th):
        if (err != 0):
            _oi_logging.error("Error getting sensor thresholds: " + str(err))
            self.Destroy()
            return
        for i in th.split(':'):
            j = i.split()
            self.thresholds[j[0]].SetValue(j[1])
        self.Show()

    def sensor_set_thresholds_cb(self, sensor, err):
        if (err):
            _oi_logging.error("Unable to set sensor thresholds: " + str(err))
        else:
            sensor.get_thresholds(self.s)
        self.Close()


class SensorEventEnablesSet(wx.Dialog):
    def __init__(self, s):
        wx.Dialog.__init__(self, None, -1, "Set Event Enables for " + str(s),
                           size=wx.Size(400, 250))
        self.s = s
        sizer = wx.BoxSizer(wx.VERTICAL)

        sbox = scrolled.ScrolledPanel(self, -1, size=wx.Size(400, 200))
        sbox_sizer = wx.BoxSizer(wx.VERTICAL)
        
        self.enable = wx.CheckBox(sbox, -1, "Enable Events")
        sbox_sizer.Add(self.enable, 0, wx.ALIGN_LEFT | wx.ALL, 2)
        self.scanning = wx.CheckBox(sbox, -1, "Scanning")
        sbox_sizer.Add(self.scanning, 0, wx.ALIGN_LEFT | wx.ALL, 2)

        self.event_enables = { }
        if (self.s.event_support == OpenIPMI.EVENT_SUPPORT_PER_STATE):
            for the in s.events_supported:
                if (s.is_threshold):
                    the_box = wx.CheckBox(sbox, -1,
                                          threshold_event_str_to_full(the))
                else:
                    name = s.events_supported_name[the]
                    the_box = wx.CheckBox(sbox, -1,
                                          discrete_event_str_to_full(the, name))
                self.event_enables[the] = the_box
                sbox_sizer.Add(the_box, 0, wx.ALIGN_LEFT | wx.ALL, 2)
        sbox.SetupScrolling()
        sbox.SetSizer(sbox_sizer)
        sizer.Add(sbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(self, -1, "Cancel")
        wx.EVT_BUTTON(self, cancel.GetId(), self.cancel)
        box.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(self, -1, "Ok")
        wx.EVT_BUTTON(self, ok.GetId(), self.ok)
        box.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.SetSizer(sizer)
        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();

        self.setting = False
        if (s.sensor_id.to_sensor(self) != 0):
            self.Destroy()

    def cancel(self, event):
        self.Close()

    def ok(self, event):
        tlist = [ ]
        if (self.enable.GetValue()):
            tlist.append("events")
        if (self.scanning.GetValue()):
            tlist.append("scanning")
        for ths in self.event_enables.iteritems():
            if ths[1].GetValue():
                tlist.append(ths[0])
        self.event_enable_str = " ".join(tlist)
        rv = self.s.sensor_id.to_sensor(self)
        if (rv == 0):
            rv = self.err
        if (rv != 0):
            _oi_logging.error("Error setting sensor event enables: " + str(rv))
            self.Close()

    def OnClose(self, event):
        self.Destroy()

    def sensor_cb(self, sensor):
        if (self.setting):
            self.err = sensor.set_event_enables(self.event_enable_str, self)
        else:
            rv = sensor.get_event_enables(self)
            if (rv != 0):
                _oi_logging.error("Error getting sensor event enables: " + str(rv))
                self.Destroy()
                return
            self.setting = True

    def sensor_get_event_enable_cb(self, sensor, err, st):
        if (err != 0):
            _oi_logging.error("Error getting sensor event enables: " + str(err))
            self.Destroy()
            return
        for i in st.split(' '):
            if (i == "events"):
                self.enable.SetValue(True)
            elif (i == "scanning"):
                self.scanning.SetValue(True)
            elif (i == "busy"):
                pass
            elif (self.s.event_support == OpenIPMI.EVENT_SUPPORT_PER_STATE):
                try:
                    self.event_enables[i].SetValue(True)
                except:
                    _oi_logging.warning("Sensor " + s.name + " returned enable "
                                    + i + " but the sensor reports it in a"
                                    + " callback.")
        self.Show()

    def sensor_event_enable_cb(self, sensor, err):
        if (err):
            _oi_logging.error("Unable to set sensor event enables: " + str(err))
        else:
            sensor.get_event_enables(self.s)
        self.Close()


class Sensor:
    def __init__(self, e, sensor):
        self.e = e
        self.name = sensor.get_name()
        self.sensor_id = sensor.get_id()
        self.ui = e.ui
        ui = self.ui
        self.updater = SensorRefreshData(self)
        ui.add_sensor(self.e, self)
        self.in_warning = False
        self.in_severe = False
        self.in_critical = False
        self.ui.append_item(self, "Sensor Type",
                            sensor.get_sensor_type_string())
        self.ui.append_item(self, "Event Reading Type",
                            sensor.get_event_reading_type_string())
        m = sensor.get_mc()
        self.ui.append_item(self, "Msg Routing Info",
                            "MC: " + m.get_name()
                            + "  LUN:" + str(sensor.get_lun())
                            + "  Num:" + str(sensor.get_num()))
                            
        self.event_support = sensor.get_event_support()
        es = self.event_support
        self.ui.append_item(self, "Event Support",
                            OpenIPMI.get_event_support_string(es))
        if ((es == OpenIPMI.EVENT_SUPPORT_PER_STATE)
            or (es == OpenIPMI.EVENT_SUPPORT_ENTIRE_SENSOR)):
            self.event_enables = self.ui.append_item(self, "Event Enables",
                                      None,
                                      data = SensorInfoGetter(self,
                                                       "get_event_enables"))

        sensor.add_event_handler(self)
        sensor.get_value(self)

        self.auto_rearm = sensor.get_supports_auto_rearm()

        self.is_threshold = (sensor.get_event_reading_type()
                             == OpenIPMI.EVENT_READING_TYPE_THRESHOLD)
        if (self.is_threshold):
            self.threshold_sensor_units = sensor.get_base_unit_string()
            modifier = sensor.get_modifier_unit_use();
            if (modifier == OpenIPMI.MODIFIER_UNIT_BASE_DIV_MOD):
               self.threshold_sensor_units += "/"
            elif (modifier == OpenIPMI.MODIFIER_UNIT_BASE_MULT_MOD):
               self.threshold_sensor_units += "*"
            modifier = sensor.get_modifier_unit_string()
            if (modifier != "unspecified"):
                self.threshold_sensor_units += modifier
            self.threshold_sensor_units += sensor.get_rate_unit_string()
            if (sensor.get_percentage()):
                self.threshold_sensor_units += '%'

            self.events_supported = [ ]
            if (es != OpenIPMI.EVENT_SUPPORT_NONE):
                for i in threshold_event_strings:
                    ival = [ 0 ]
                    rv = sensor.threshold_event_supported(i, ival)
                    if (rv == 0) and (ival[0] != 0):
                        self.events_supported.append(i)
                self.ui.append_item(self, "Threshold Events Supported",
                                    ' '.join(self.events_supported))

            sval = ""
            fval = [ 0.0 ]
            rv = sensor.get_nominal_reading(fval)
            if (rv == 0):
                sval += "  Nominal:" + str(fval[0])
            rv = sensor.get_sensor_min(fval)
            if (rv == 0):
                sval += "  Min:" + str(fval[0])
            rv = sensor.get_sensor_max(fval)
            if (rv == 0):
                sval += "  Max:" + str(fval[0])
            rv = sensor.get_normal_min(fval)
            if (rv == 0):
                sval += "  NormalMin:" + str(fval[0])
            rv = sensor.get_normal_max(fval)
            if (rv == 0):
                sval += "  NormalMax:" + str(fval[0])
            if (sval != ""):
                sval = sval.strip()
                self.ui.append_item(self, "Ranges", sval);

            self.threshold_support = sensor.get_threshold_access()
            ts = self.threshold_support
            self.ui.append_item(self, "Threshold Support",
                              OpenIPMI.get_threshold_access_support_string(ts))
            sval = ""
            rval = ""
            if (ts != OpenIPMI.THRESHOLD_ACCESS_SUPPORT_NONE):
                wval = ""
                ival = [ 0 ]
                for th in threshold_strings:
                    rv = sensor.threshold_settable(th, ival)
                    if (rv == 0) and (ival[0] == 1):
                        sval += " " + th
                    rv = sensor.threshold_readable(th, ival)
                    if (rv == 0) and (ival[0] == 1):
                        rval += " " + th
                    rv = sensor.threshold_reading_supported(th, ival)
                    if (rv == 0) and (ival[0] == 1):
                        wval += " " + th
                if (wval != ""):
                    wval = wval.strip()
                    self.ui.append_item(self, "Thresholds Reported", wval)

            if ((ts == OpenIPMI.THRESHOLD_ACCESS_SUPPORT_READABLE)
                or (ts == OpenIPMI.THRESHOLD_ACCESS_SUPPORT_SETTABLE)):
                if (sval != ""):
                    sval = sval.strip()
                    self.ui.append_item(self, "Settable Thresholds", sval)
                if (rval != ""):
                    rval = rval.strip()
                    self.ui.append_item(self, "Readable Thresholds", rval)
                        
                self.thresholds = self.ui.append_item(self, "Thresholds",
                                      None,
                                      data = SensorInfoGetter(self,
                                                       "get_thresholds"))
            else:
                sval = ""

            self.settable_thresholds = sval

            self.hysteresis_support = sensor.get_hysteresis_support()
            hs = self.hysteresis_support
            self.ui.append_item(self, "Hysteresis Support",
                                OpenIPMI.get_hysteresis_support_string(hs))
            if ((hs == OpenIPMI.HYSTERESIS_SUPPORT_READABLE)
                or (hs == OpenIPMI.HYSTERESIS_SUPPORT_SETTABLE)):
                self.hysteresis =  self.ui.append_item(self, "Hysteresis",
                                     None,
                                     data = SensorInfoGetter(self,
                                                             "get_hysteresis"))
        else:
            self.hysteresis_support = OpenIPMI.HYSTERESIS_SUPPORT_NONE
            self.threshold_support = OpenIPMI.THRESHOLD_ACCESS_SUPPORT_NONE

            self.events_supported = [ ]
            self.events_supported_name = { }
            self.states_supported = [ ]
            self.states_supported_name = { }
            if (es != OpenIPMI.EVENT_SUPPORT_NONE):
                for i in range(0, 15):
                    ival = [ 0 ]
                    rv = sensor.discrete_event_readable(i, ival)
                    if (rv == 0) and (ival[0] != 0):
                        self.states_supported.append(str(i))
                    name = sensor.reading_name_string(i)
                    self.states_supported_name[str(i)] = name
                    for j in ['a', 'd']:
                        ival = [ 0 ]
                        sval = str(i) + j
                        rv = sensor.discrete_event_supported(sval, ival)
                        if (rv == 0) and (ival[0] != 0):
                            self.events_supported.append(sval)
                            self.events_supported_name[sval] = name
                            
                self.ui.append_item(self, "Events Supported",
                                    ' '.join(self.events_supported))
                self.ui.append_item(self, "States Reported",
                                    ' '.join(self.states_supported))
                names = self.ui.append_item(self, "State Names", "")
                for i in self.states_supported:
                    self.ui.append_item(None, str(i),
                                        self.states_supported_name[str(i)],
                                        parent=names)

    def __str__(self):
        return self.name

    def DoUpdate(self):
        self.sensor_id.to_sensor(self.updater)

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        doit = False
        if (self.event_support != OpenIPMI.EVENT_SUPPORT_NONE):
            item = menu.Append(id_st+1, "Rearm")
            wx.EVT_MENU(self.ui, id_st+1, self.Rearm)
            doit = True
        if (self.threshold_support == OpenIPMI.THRESHOLD_ACCESS_SUPPORT_SETTABLE):
            item = menu.Append(id_st+2, "Set Thresholds")
            wx.EVT_MENU(self.ui, id_st+2, self.SetThresholds)
            doit = True
        if (self.hysteresis_support == OpenIPMI.HYSTERESIS_SUPPORT_SETTABLE):
            item = menu.Append(id_st+3, "Set Hysteresis")
            wx.EVT_MENU(self.ui, id_st+3, self.SetHysteresis)
            doit = True
        if ((self.event_support == OpenIPMI.EVENT_SUPPORT_PER_STATE)
            or (self.event_support == OpenIPMI.EVENT_SUPPORT_ENTIRE_SENSOR)):
            item = menu.Append(id_st+4, "Set Event Enables")
            wx.EVT_MENU(self.ui, id_st+4, self.SetEventEnables)
            doit = True

        if (doit):
            self.ui.PopupMenu(menu, self.ui.get_item_pos(eitem))
        menu.Destroy()

    def Rearm(self, event):
        pass
    
    def SetThresholds(self, event):
        SensorThresholdsSet(self)
    
    def SetHysteresis(self, event):
        SensorHysteresisSet(self)
    
    def SetEventEnables(self, event):
        SensorEventEnablesSet(self)
    
    def remove(self):
        self.e.sensors.pop(self.name)
        self.ui.remove_sensor(self)

    def handle_threshold_states(self, states):
        th = states.split()
        while len(th) > 0:
            v = th[0]
            del th[0]

            if (v == "un") or (v == "ln"):
                if (not self.in_warning):
                    self.in_warning = True
                    self.ui.incr_item_warning(self.treeroot)
            else:
                if (self.in_warning):
                    self.in_warning = False
                    self.ui.decr_item_warning(self.treeroot)

            if (v == "uc") or (v == "lc"):
                if (not self.in_severe):
                    self.in_severe = True
                    self.ui.incr_item_severe(self.treeroot)
            else:
                if (self.in_severe):
                    self.in_severe = False
                    self.ui.decr_item_severe(self.treeroot)

            if (v == "ur") or (v == "lr"):
                if (not self.in_critical):
                    self.in_critical = True
                    self.ui.incr_item_critical(self.treeroot)
            else:
                if (self.in_critical):
                    self.in_critical = False
                    self.ui.decr_item_critical(self.treeroot)


    def threshold_reading_cb(self, sensor, err, raw_set, raw, value_set,
                             value, states):
        if (err):
            self.ui.set_item_text(self.treeroot, None)
            return
        v = ""
        if (value_set):
            v += str(value) + self.threshold_sensor_units
        if (raw_set):
            v += " (" + str(raw) + ")"
        v += ": " + states
        self.ui.set_item_text(self.treeroot, v)
        self.handle_threshold_states(states)
        
    def discrete_states_cb(self, sensor, err, states):
        if (err):
            self.ui.set_item_text(self.treeroot, None)
            return
        self.ui.set_item_text(self.treeroot, states)
        
    def sensor_get_event_enable_cb(self, sensor, err, states):
        if (err != 0):
            self.ui.set_item_text(self.event_enables, None)
            return
        self.ui.set_item_text(self.event_enables, states)

    def sensor_get_hysteresis_cb(self, sensor, err, positive, negative):
        if (err != 0):
            self.ui.set_item_text(self.hysteresis, None)
            return
        self.ui.set_item_text(self.hysteresis,
                              "Positive:" + str(positive)
                              + " Negative:" + str(negative))

    def sensor_get_thresholds_cb(self, sensor, err, th):
        if (err != 0):
            self.ui.set_item_text(self.thresholds, None)
            return
        self.ui.set_item_text(self.thresholds, th)

    def threshold_event_cb(self, sensor, event_spec, raw_set, raw,
                           value_set, value, event):
        self.handle_threshold_states(event_spec)
        sensor.get_value(self)
        
    def discrete_event_cb(self, sensor, event_spec, severity, old_severity,
                          event):
        pass
