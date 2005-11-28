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

    def __str__(self):
        return self.name

    def DoUpdate(self):
        self.sensor_id.convert_to_sensor(self.updater)

    def remove(self):
        self.e.sensors.pop(self.name)
        self.ui.remove_sensor(self)

    def threshold_reading_cb(self, sensor, err, raw_set, raw, value_set,
                             value, states):
        if (err):
            self.ui.set_item_text(self.treeroot, str(self), None)
            return
        v = ""
        if (value_set):
            v = v + str(value)
        if (raw_set):
            v = v + "(" + str(raw) + ")"
        v = v + ": " + states
        self.ui.set_item_text(self.treeroot, str(self), v)
        
    def discrete_states_cb(self, sensor, err, states):
        if (err):
            self.ui.set_item_text(self.treeroot, str(self), None)
            return
        self.ui.set_item_text(self.treeroot, str(self), states)
        
