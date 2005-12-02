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
        self.s.sensor_id.convert_to_sensor(self)

    def sensor_cb(self, sensor):
        getattr(sensor, self.func)(self.s)


threshold_strings = [ 'un', 'uc', 'ur', 'ln', 'lc', 'lr' ]
threshold_event_strings = [ 'unha', 'unhd', 'unla', 'unld',
                            'ucha', 'uchd', 'ucla', 'ucld',
                            'urha', 'urhd', 'urla', 'urld',
                            'lnha', 'lnhd', 'lnla', 'lnld',
                            'lcha', 'lchd', 'lcla', 'lcld',
                            'lrha', 'lrhd', 'lrla', 'lrld' ]
    
class Sensor:
    def __init__(self, e, sensor):
        self.e = e
        self.name = sensor.get_name()
        self.sensor_id = sensor.get_id()
        self.ui = e.ui
        ui = self.ui
        self.updater = SensorRefreshData(self)
        ui.add_sensor(self.e, self)
        sensor.get_value(self)
        self.in_warning = False
        self.in_severe = False
        self.in_critical = False
        self.ui.append_item(self, "Sensor Type\t\t",
                            sensor.get_sensor_type_string())
        self.ui.append_item(self, "Event Reading Type",
                            sensor.get_event_reading_type_string())
        m = sensor.get_mc()
        self.ui.append_item(self, "Msg Routing Info\t",
                            "MC: " + m.get_name()
                            + "  LUN:" + str(sensor.get_lun())
                            + "  Num:" + str(sensor.get_num()))
                            
        self.event_support = sensor.get_event_support()
        es = self.event_support
        self.ui.append_item(self, "Event Support\t\t",
                            OpenIPMI.get_event_support_string(es))
        if ((es == OpenIPMI.EVENT_SUPPORT_PER_STATE)
            or (es == OpenIPMI.EVENT_SUPPORT_ENTIRE_SENSOR)):
            self.event_enables = self.ui.append_item(self, "Event Enables\t\t",
                                      None,
                                      data = SensorInfoGetter(self,
                                                       "get_event_enables"))
            sensor.get_event_enables(self)

        # OP: rearm (if no auto_rearm)
        # OP: set thresholds
        # OP: set event enables

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
                self.ui.append_item(self, "Ranges\t\t\t", sval);

            self.threshold_support = sensor.get_threshold_access()
            ts = self.threshold_support
            self.ui.append_item(self, "Threshold Support\t",
                              OpenIPMI.get_threshold_access_support_string(ts))
            if (ts != OpenIPMI.THRESHOLD_ACCESS_SUPPORT_NONE):
                sval = ""
                rval = ""
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
                        
                self.thresholds = self.ui.append_item(self, "Thresholds\t\t",
                                      None,
                                      data = SensorInfoGetter(self,
                                                       "get_thresholds"))
                sensor.get_thresholds(self)

            self.hysteresis_support = sensor.get_hysteresis_support()
            hs = self.hysteresis_support
            self.ui.append_item(self, "Hysteresis Support\t",
                                OpenIPMI.get_hysteresis_support_string(hs))
            if ((hs == OpenIPMI.HYSTERESIS_SUPPORT_READABLE)
                or (hs == OpenIPMI.HYSTERESIS_SUPPORT_SETTABLE)):
                self.hysteresis =  self.ui.append_item(self, "Hysteresis\t\t",
                                     None,
                                     data = SensorInfoGetter(self,
                                                             "get_hysteresis"))
                sensor.get_hysteresis(self)
                
    def __str__(self):
        return self.name

    def DoUpdate(self):
        self.sensor_id.convert_to_sensor(self.updater)

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
