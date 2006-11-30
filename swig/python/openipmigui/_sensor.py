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
import OpenIPMI
import gui_popup
import gui_setdialog
import _oi_logging

class SensorRefreshData:
    def __init__(self, s):
        self.s = s
        return

    def sensor_cb(self, sensor):
        if (sensor.is_readable()):
            sensor.get_value(self.s)
        return

    pass


class SensorInfoGetter:
    def __init__(self, s, func):
        self.s = s;
        self.func = func;
        return

    def DoUpdate(self):
        self.s.sensor_id.to_sensor(self)
        return

    def sensor_cb(self, sensor):
        getattr(sensor, self.func)(self.s)
        return

    pass


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
        pass
    if (s[3] == 'a'):
        rv += " assertion"
    else:
        rv += " deassertion"
        pass
    return rv

def discrete_event_str_to_full(s, name):
    l = len(s)
    num = int(s[0:l-1])
    t = s[l-1:l]
    if (t == 'a'):
        t = 'assertion'
    else:
        t = 'deassertion'
        pass
    return s[0:l-1] + ' ' + t + ' (' + name + ')'

class SensorHysteresisSet:
    def __init__(self, s):
        self.s = s
        self.setting = False
        if (s.sensor_id.to_sensor(self) != 0):
            s.gui.ReportError("Unable to convert " + s.name
                              + "to a sensor for hysteresis setting")
            pass
        return
        
    def ok(self, vals):
        self.positive = int(vals[0])
        self.negative = int(vals[1])
        rv = self.s.sensor_id.to_sensor(self)
        if (rv == 0):
            rv = self.err
            pass
        if (rv != 0):
            return ("Error setting sensor thresholds: "
                    + OpenIPMI.get_error_string(rv))
        return

    def sensor_cb(self, sensor):
        if (self.setting):
            self.err = sensor.set_hysteresis(self.positive, self.negative, self)
        else:
            sensor.get_hysteresis(self)
            self.setting = True
            pass
        return

    def sensor_get_hysteresis_cb(self, sensor, err, positive, negative):
        if (err != 0):
            _oi_logging.error("Error getting sensor hysteresis: " + str(err))
            self.Destroy()
        else:
            gui_setdialog.SetDialog("Set hysteresis for " + self.s.name,
                                    [ positive, negative ], 2, self,
                                    [ "Positive", "Negative" ])
            pass
        return

    def sensor_set_hysteresis_cb(self, sensor, err):
        if (err):
            _oi_logging.error("Unable to set sensor thresholds: " + str(err))
        else:
            sensor.get_hysteresis(self.s)
            pass
        return

    pass


class SensorThresholdsSet:
    def __init__(self, s):
        self.s = s
        self.setting = False
        if (s.sensor_id.to_sensor(self) != 0):
            s.gui.ReportError("Unable to convert " + s.name
                              + "to a sensor for threshold setting")
            pass
        return

    def ok(self, vals):
        tlist = [ ]
        i = 0
        for th in self.thresholds:
            tlist.append(th + " " + str(float(vals[i])))
            i += 1
            pass
        self.threshold_str = ":".join(tlist)
        self.setting = True
        rv = self.s.sensor_id.to_sensor(self)
        if (rv == 0):
            rv = self.err
            pass
        if (rv != 0):
            return ("Error setting sensor thresholds: "
                    + OpenIPMI.get_error_string(rv))
        return

    def sensor_cb(self, sensor):
        if (self.setting):
            self.err = sensor.set_thresholds(self.threshold_str, self)
        else:
            rv = sensor.get_thresholds(self)
            if (rv != 0):
                _oi_logging.error("Error getting sensor thresholds: " + str(rv))
                return
            pass
        return

    def sensor_get_thresholds_cb(self, sensor, err, th):
        if (err != 0):
            _oi_logging.error("Error getting sensor thresholds: " + str(err))
            return
        self.thresholds = [ ]
        defaults = [ ]
        labels = [ ]
        for i in th.split(':'):
            j = i.split()
            self.thresholds.append(j[0])
            defaults.append(j[1])
            labels.append(threshold_str_to_full(j[0]))
            pass
        gui_setdialog.SetDialog("Set Thresholds for " + str(self.s),
                                defaults, len(defaults), self, labels)
        return

    def sensor_set_thresholds_cb(self, sensor, err):
        if (err):
            _oi_logging.error("Unable to set sensor thresholds: " + str(err))
        else:
            sensor.get_thresholds(self.s)
            pass
        return

    pass


class SensorEventEnablesSet:
    def __init__(self, s):
        self.s = s
        self.setting = False
        if (s.sensor_id.to_sensor(self) != 0):
            s.gui.ReportError("Unable to convert " + s.name
                              + "to a sensor for event enable setting")
            pass
        return

    def ok(self, vals):
        tlist = [ ]
        if (vals[0]):
            tlist.append("events")
            pass
        del vals[0]
        if (vals[0]):
            tlist.append("scanning")
            pass
        del vals[0]

        for en in self.enables:
            if vals[0]:
                tlist.append(en)
                pass
            del vals[0]
            pass
        self.event_enable_str = " ".join(tlist)
        self.setting = True
        rv = self.s.sensor_id.to_sensor(self)
        if (rv == 0):
            rv = self.err
            pass
        if (rv != 0):
            return ("Error setting sensor event enables: "
                    + OpenIPMI.get_error_string(rv))
        return
        
    def sensor_cb(self, sensor):
        if (self.setting):
            self.err = sensor.set_event_enables(self.event_enable_str, self)
        else:
            rv = sensor.get_event_enables(self)
            if (rv != 0):
                _oi_logging.error("Error getting sensor event enables: "
                                  + str(rv))
                return
            pass
        return

    def sensor_get_event_enable_cb(self, sensor, err, st):
        if (err != 0):
            _oi_logging.error("Error getting sensor event enables: "
                              + str(err))
            return
        defaults = [ False, False ]
        labels = [ "Enable Events", "Scanning" ]
        en = { }
        for i in self.s.events_supported:
            en[i] = False
            pass
        for i in st.split(' '):
            if (i == "events"):
                defaults[0] = True
            elif (i == "scanning"):
                defaults[1] = True
            elif (i == "busy"):
                pass
            elif (self.s.event_support == OpenIPMI.EVENT_SUPPORT_PER_STATE):
                en[i] = True
                pass
            pass
        
        self.enables = [ ]
        for i in self.s.events_supported:
            defaults.append(en[i])
            self.enables.append(i)
            if (self.s.is_threshold):
                labels.append(threshold_event_str_to_full(i))
            else:
                name = s.events_supported_name[i]
                labels.append(discrete_event_str_to_full(i, name))
                pass
            pass

        gui_setdialog.SetDialog("Set Event Enables for " + str(self.s),
                                defaults, len(defaults), self, labels)
        return

    def sensor_event_enable_cb(self, sensor, err):
        if (err):
            _oi_logging.error("Unable to set sensor event enables: " + str(err))
        else:
            sensor.get_event_enables(self.s)
            pass
        return

    pass


class Sensor:
    def __init__(self, e, sensor):
        if (e.ui.in_destroy):
            return
        self.e = e
        self.name = sensor.get_name()
        e.sensors[self.name] = self
        self.sensor_id = sensor.get_id()
        self.ui = e.ui
        ui = self.ui
        self.destroyed = False
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
            pass

        sensor.add_event_handler(self)
        if (sensor.is_readable()):
            sensor.get_value(self)
            pass
        else:
            self.ui.set_item_text(self.treeroot, "(not readable)")
            pass

        self.auto_rearm = sensor.get_supports_auto_rearm()

        self.is_threshold = (sensor.get_event_reading_type()
                             == OpenIPMI.EVENT_READING_TYPE_THRESHOLD)
        if (self.is_threshold):
            self.threshold_sensor_units = sensor.get_base_unit_string()
            modifier = sensor.get_modifier_unit_use();
            if (modifier == OpenIPMI.MODIFIER_UNIT_BASE_DIV_MOD):
               self.threshold_sensor_units += "/"
               pass
            elif (modifier == OpenIPMI.MODIFIER_UNIT_BASE_MULT_MOD):
               self.threshold_sensor_units += "*"
               pass
            modifier = sensor.get_modifier_unit_string()
            if (modifier != "unspecified"):
                self.threshold_sensor_units += modifier
                pass
            self.threshold_sensor_units += sensor.get_rate_unit_string()
            if (sensor.get_percentage()):
                self.threshold_sensor_units += '%'
                pass

            self.events_supported = [ ]
            if (es != OpenIPMI.EVENT_SUPPORT_NONE):
                for i in threshold_event_strings:
                    ival = [ 0 ]
                    rv = sensor.threshold_event_supported(i, ival)
                    if (rv == 0) and (ival[0] != 0):
                        self.events_supported.append(i)
                        pass
                    pass
                self.ui.append_item(self, "Threshold Events Supported",
                                    ' '.join(self.events_supported))

                pass
            sval = ""
            fval = [ 0.0 ]
            rv = sensor.get_nominal_reading(fval)
            if (rv == 0):
                sval += "  Nominal:" + str(fval[0])
                pass
            rv = sensor.get_sensor_min(fval)
            if (rv == 0):
                sval += "  Min:" + str(fval[0])
                pass
            rv = sensor.get_sensor_max(fval)
            if (rv == 0):
                sval += "  Max:" + str(fval[0])
                pass
            rv = sensor.get_normal_min(fval)
            if (rv == 0):
                sval += "  NormalMin:" + str(fval[0])
                pass
            rv = sensor.get_normal_max(fval)
            if (rv == 0):
                sval += "  NormalMax:" + str(fval[0])
                pass
            if (sval != ""):
                sval = sval.strip()
                self.ui.append_item(self, "Ranges", sval);
                pass

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
                        pass
                    rv = sensor.threshold_readable(th, ival)
                    if (rv == 0) and (ival[0] == 1):
                        rval += " " + th
                        pass
                    rv = sensor.threshold_reading_supported(th, ival)
                    if (rv == 0) and (ival[0] == 1):
                        wval += " " + th
                        pass
                    pass
                if (wval != ""):
                    wval = wval.strip()
                    self.ui.append_item(self, "Thresholds Reported", wval)
                    pass

            if ((ts == OpenIPMI.THRESHOLD_ACCESS_SUPPORT_READABLE)
                or (ts == OpenIPMI.THRESHOLD_ACCESS_SUPPORT_SETTABLE)):
                if (sval != ""):
                    sval = sval.strip()
                    self.ui.append_item(self, "Settable Thresholds", sval)
                    pass
                if (rval != ""):
                    rval = rval.strip()
                    self.ui.append_item(self, "Readable Thresholds", rval)
                    pass
                        
                self.thresholds = self.ui.append_item(self, "Thresholds",
                                      None,
                                      data = SensorInfoGetter(self,
                                                       "get_thresholds"))
                pass
            else:
                sval = ""
                pass

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
                pass
            pass
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
                            pass
                        pass
                    pass
                            
                self.ui.append_item(self, "Events Supported",
                                    ' '.join(self.events_supported))
                self.ui.append_item(self, "States Reported",
                                    ' '.join(self.states_supported))
                names = self.ui.append_item(self, "State Names", "")
                for i in self.states_supported:
                    self.ui.append_item(None, str(i),
                                        self.states_supported_name[str(i)],
                                        parent=names)
                    pass
                pass
            pass
        return

    def __str__(self):
        return self.name

    def DoUpdate(self):
        self.sensor_id.to_sensor(self.updater)
        return

    def HandleMenu(self, event):
        if (self.impt_data == None):
            l = [ [ "Add to watch values", self.add_impt ] ]
            pass
        else:
            l = [ [ "Remove from watch values", self.remove_impt ] ]
            pass
        if (self.event_support != OpenIPMI.EVENT_SUPPORT_NONE):
            l.append( ("Rearm", self.Rearm) )
            pass
        if (self.threshold_support == OpenIPMI.THRESHOLD_ACCESS_SUPPORT_SETTABLE):
            l.append( ("Set Thresholds", self.SetThresholds) )
            pass
        if (self.hysteresis_support == OpenIPMI.HYSTERESIS_SUPPORT_SETTABLE):
            l.append( ("Set Hysteresis", self.SetHysteresis) )
            pass
        if ((self.event_support == OpenIPMI.EVENT_SUPPORT_PER_STATE)
            or (self.event_support == OpenIPMI.EVENT_SUPPORT_ENTIRE_SENSOR)):
            l.append( ("Set Event Enables", self.SetEventEnables) )
            pass

        if (len(l) > 0):
            gui_popup.popup(self.ui, event, l)
            pass
        return

    def add_impt(self, event):
        self.ui.add_impt_data("sensor", str(self), self)
        return
        
    def remove_impt(self, event):
        self.ui.remove_impt_data(self.impt_data)
        return
        
    def Rearm(self, event):
        return
    
    def SetThresholds(self, event):
        SensorThresholdsSet(self)
        return
    
    def SetHysteresis(self, event):
        SensorHysteresisSet(self)
        return
    
    def SetEventEnables(self, event):
        SensorEventEnablesSet(self)
        return
    
    def remove(self):
        self.e.sensors.pop(self.name)
        self.ui.remove_sensor(self)
        self.destroyed = True
        self.e = None
        self.updater = None
        self.ui = None
        return

    def handle_threshold_states(self, states):
        if (self.destroyed):
            return
        th = states.split()
        while len(th) > 0:
            v = th[0]
            del th[0]

            if (v == "un") or (v == "ln"):
                if (not self.in_warning):
                    self.in_warning = True
                    self.ui.incr_item_warning(self.treeroot)
                    pass
                pass
            else:
                if (self.in_warning):
                    self.in_warning = False
                    self.ui.decr_item_warning(self.treeroot)
                    pass
                pass

            if (v == "uc") or (v == "lc"):
                if (not self.in_severe):
                    self.in_severe = True
                    self.ui.incr_item_severe(self.treeroot)
                    pass
                pass
            else:
                if (self.in_severe):
                    self.in_severe = False
                    self.ui.decr_item_severe(self.treeroot)
                    pass
                pass

            if (v == "ur") or (v == "lr"):
                if (not self.in_critical):
                    self.in_critical = True
                    self.ui.incr_item_critical(self.treeroot)
                    pass
                pass
            else:
                if (self.in_critical):
                    self.in_critical = False
                    self.ui.decr_item_critical(self.treeroot)
                    pass
                pass
            pass
        return

    def threshold_reading_cb(self, sensor, err, raw_set, raw, value_set,
                             value, states):
        if (self.destroyed):
            return
        if (err):
            self.ui.set_item_text(self.treeroot, None)
            return
        v = ""
        if (value_set):
            v += str(value) + self.threshold_sensor_units
            pass
        if (raw_set):
            v += " (" + str(raw) + ")"
            pass
        v += ": " + states
        self.ui.set_item_text(self.treeroot, v)
        self.handle_threshold_states(states)
        return
        
    def discrete_states_cb(self, sensor, err, states):
        if (self.destroyed):
            return
        if (err):
            self.ui.set_item_text(self.treeroot, None)
            return
        self.ui.set_item_text(self.treeroot, states)
        return
        
    def sensor_get_event_enable_cb(self, sensor, err, states):
        if (self.destroyed):
            return
        if (err != 0):
            self.ui.set_item_text(self.event_enables, None)
            return
        self.ui.set_item_text(self.event_enables, states)
        return

    def sensor_get_hysteresis_cb(self, sensor, err, positive, negative):
        if (self.destroyed):
            return
        if (err != 0):
            self.ui.set_item_text(self.hysteresis, None)
            return
        self.ui.set_item_text(self.hysteresis,
                              "Positive:" + str(positive)
                              + " Negative:" + str(negative))
        return

    def sensor_get_thresholds_cb(self, sensor, err, th):
        if (self.destroyed):
            return
        if (err != 0):
            self.ui.set_item_text(self.thresholds, None)
            return
        self.ui.set_item_text(self.thresholds, th)
        return

    def threshold_event_cb(self, sensor, event_spec, raw_set, raw,
                           value_set, value, event):
        if (self.destroyed):
            return OpenIPMI.EVENT_NOT_HANDLED
        self.handle_threshold_states(event_spec)
        sensor.get_value(self)
        return OpenIPMI.EVENT_NOT_HANDLED
        
    def discrete_event_cb(self, sensor, event_spec, severity, old_severity,
                          event):
        if (self.destroyed):
            return OpenIPMI.EVENT_NOT_HANDLED
        return OpenIPMI.EVENT_NOT_HANDLED
    
    pass
