# _entity.py
#
# openipmi GUI handling for entities
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
import _sensor
import _control

class Entity:
    def __init__(self, d, entity):
        self.d = d
        self.name = entity.get_name()
        self.entity_id = entity.get_id()
        d.entities[self.name] = self
        self.ui = d.ui
        if (entity.is_child()):
            entity.iterate_parents(self)
            self.ui.add_entity(self.d, self, parent=self.parent)
            self.parent = None # Don't leave circular reference
        else:
            self.ui.add_entity(self.d, self)
        eid = entity.get_id_string()
        if (eid == None):
            eid = entity.get_entity_id_string()
        if (eid != None):
            self.ui.set_item_text(self.treeroot, eid)
        self.sensors = { }
        self.controls = { }
        entity.add_presence_handler(self)

    def __str__(self):
        return self.name

    def entity_iter_entities_cb(self, child, parent):
        self.parent = self.d.find_or_create_entity(parent)
        
    def remove(self):
        self.d.entities.pop(self.name)
        self.ui.remove_entity(self)

    def entity_sensor_update_cb(self, op, entity, sensor):
        if (op == "added"):
            e = _sensor.Sensor(self, sensor)
        elif (op == "removed"):
            self.sensors[sensor.get_name()].remove()

    def entity_control_update_cb(self, op, entity, control):
        if (op == "added"):
            e = _control.Control(self, control)
        elif (op == "removed"):
            self.controls[control.get_name()].remove()

    def entity_presence_cb(self, entity, present, event):
        if (present):
            self.ui.set_item_active(self.treeroot)
        else:
            self.ui.set_item_inactive(self.treeroot)
