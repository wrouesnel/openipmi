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
import _oi_logging
import _sensor
import _control
import _fru
import gui_popup
import gui_setdialog

class EntityOp:
    def __init__(self, e, func):
        self.e = e
        self.func = func
        return

    def DoOp(self):
        rv = self.e.entity_id.to_entity(self)
        if (rv == 0):
            rv = self.rv
            pass
        return rv;

    def entity_cb(self, entity):
        self.rv = getattr(entity, self.func)(self.e)
        return

    pass

class EntityFruViewer:
    def __init__(self, e):
        self.e = e
        self.e.entity_id.to_entity(self)
        return

    def entity_cb(self, entity):
        fru = entity.get_fru()
        if (fru == None):
            return
        _fru.FruInfoDisplay(fru, str(self.e))
        return

    pass

class ActivationTimeSetter:
    def __init__(self, e, name, func):
        self.e = e
        self.name = name
        self.func = func

        self.err = 0
        rv = e.entity_id.to_entity(self)
        if (rv == 0):
            rv = self.err
            pass
        if (rv):
            _oi_logging.error("Error doing entity cb in activation time setter: "
                          + str(rv))
            pass

        return

    def ok(self, val):
        self.acttime = int(val)
        rv = self.e.entity_id.to_entity(self)
        if (rv == 0):
            rv = self.err
            pass
        if (rv != 0):
            return ("Error setting activation time: "
                    + OpenIPMI.get_error_string(rv))
        return

    def entity_cb(self, entity):
        if (self.setting):
            self.err = getattr(entity, 'set_' + self.func)(None)
        else:
            self.err = getattr(entity, 'get_' + self.func)(self)
            pass
        return

    def entity_hot_swap_get_time_cb(self, entity, err, time):
        if (err):
            _oi_logging.error("Error getting activation time: " + str(err))
            return
        gui_setdialog.SetDialog("Set " + self.name + " for " + str(self.e),
                                [ time ],
                                1,
                                self)
        return

    pass

class Entity:
    def __init__(self, d, entity):
        self.d = d
        self.ui = d.ui
        self.name = entity.get_name()
        self.entity_id = entity.get_id()
        self.entity_id_str = entity.get_entity_id_string()
        self.sensors = { }
        self.controls = { }
        self.children = { }
        entity.add_presence_handler(self)
        entity.add_hot_swap_handler(self)
        entity.add_sensor_update_handler(self)
        entity.add_control_update_handler(self)

        d.entities[self.name] = self

        self.destroyed = False

        # Find my parent and put myself in that hierarchy
        self.parent_id = None
        self.parent = None
        self.eeop = "fparent"
        entity.iterate_parents(self)
        self.ui.add_entity(self.d, self, parent=self.parent)
        if (self.parent != None):
            self.parent.children[self.name] = self.name
            self.parent_name = self.parent.name
            pass
        else:
            self.parent_name = None
            pass
        self.parent = None # Don't leave circular reference

        self.hot_swap = 'No'
        self.hot_swap_state = ''
        self.create_my_items()

        self.Changed(entity)
        return

    def create_my_items(self):
        self.ui.append_item(self, 'Entity ID', self.entity_id_str)
        self.typeitem = self.ui.append_item(self, 'Type', None)
        self.idstringitem = self.ui.append_item(self, 'ID String', None)
        self.psatitem = self.ui.append_item(self,
                                            'Presence Sensor Always There',
                                            None)
        self.slotnumitem = self.ui.append_item(self, 'Slot Number', None)
        self.mcitem = self.ui.append_item(self, 'MC', None)
        self.hotswapitem = self.ui.append_item(self, 'Hot Swap', self.hot_swap)
        return
    
    def __str__(self):
        return self.name

    def HandleMenu(self, event):
        if (self.impt_data == None):
            menul = [ [ "Add to watch values", self.add_impt ] ]
            pass
        else:
            menul = [ [ "Remove from watch values", self.remove_impt ] ]
            pass
        if (self.is_fru):
            menul.append(["View FRU Data", self.ViewFruData])
            pass
            
        if (self.hot_swap == "Managed"):
            menul.append(["Request Activation", self.RequestActivation])
            menul.append(["Activate", self.Activate])
            menul.append(["Deactivate", self.Deactivate])
            if (self.supports_auto_activate):
                menul.append(["Set Auto-activate Time", self.SetAutoActTime])
                pass
            if (self.supports_auto_deactivate):
                menul.append(["Set Auto-deactivate Time",
                              self.SetAutoDeactTime])
                pass
            pass

        if (len(menul) > 0):
            gui_popup.popup(self.d.ui, event, menul)
            pass
        return

    def add_impt(self, event):
        self.ui.add_impt_data("entity", str(self), self)
        return
        
    def remove_impt(self, event):
        self.ui.remove_impt_data(self.impt_data)
        return
        
    def RequestActivation(self, event):
        oper = EntityOp(self, "set_activation_requested")
        rv = oper.DoOp()
        if (rv != 0):
            _oi_logging.error("entity set activation failed: " + str(rv))
            pass
        return

    def Activate(self, event):
        oper = EntityOp(self, "activate")
        rv = oper.DoOp()
        if (rv != 0):
            _oi_logging.error("entity activation failed: " + str(rv))
            pass
        return

    def Deactivate(self, event):
        oper = EntityOp(self, "deactivate")
        rv = oper.DoOp()
        if (rv != 0):
            _oi_logging.error("entity deactivation failed: " + str(rv))
            pass
        return

    def SetAutoActTime(self, event):
        ActivationTimeSetter(self, "Activation Time", "auto_activate_time")
        return
        
    def SetAutoDeactTime(self, event):
        ActivationTimeSetter(self, "Deactivation Time", "auto_deactivate_time")
        return
        
    def ViewFruData(self, event):
        EntityFruViewer(self)
        return

    def entity_activate_cb(self, entity, err):
        if (err != 0):
            _oi_logging.error("entity activate operation failed: " + str(err))
            pass
        return
        
    def Changed(self, entity):
        # Reparent first, in case parent has changed.
        old_parent_id = self.parent_id
        reparent = False
        self.parent_id = None
        self.parent = None
        self.eeop = "fparent"
        entity.iterate_parents(self)
        if (self.parent_id != None):
            if (old_parent_id == None):
                reparent = True
                pass
            elif (self.parent_id.cmp(old_parent_id) != 0):
                reparent = True
                pass
            pass
        else:
            if (old_parent_id != None):
                reparent = True
                pass
            pass

        if (reparent):
            old_treeroot = self.treeroot
            self.eop = "deleted"
            entity.iterate_sensors(self)
            entity.iterate_controls(self)

            if (self.parent_name):
                oparent = self.d.find_entity_byname(self.parent_name)
                if (oparent):
                    del oparent.children[self.name]
                pass
            self.ui.reparent_entity(self.d, self, self.parent)
            if (self.parent != None):
                self.parent.children[self.name] = self.name
                self.parent_name = self.parent.name
                pass
            else:
                self.parent_name = None
                pass
            self.create_my_items()

            # Reparent children
            self.eeop = "repch"
            entity.iterate_children(self);
            
            self.eop = "added"
            entity.iterate_sensors(self)
            entity.iterate_controls(self)

            if (entity.is_present()):
                self.ui.set_item_active(self.treeroot);
                pass
            else:
                self.ui.set_item_inactive(self.treeroot);
                pass

            self.eop = None
            self.ui.remove_entity(old_treeroot)
            pass
        
        self.parent = None # Kill circular reference


        self.is_fru = entity.is_fru()
        
        self.id_str = entity.get_id_string()
        eid = self.id_str
        if (eid == None):
            eid = self.entity_id_str
            pass
        if (eid != None):
            self.ui.set_item_text(self.treeroot, eid)
            pass

        self.entity_type = entity.get_type()
        self.slot_number = entity.get_physical_slot_num()
        if (self.slot_number < 0):
            self.slot_number = None
            pass

        self.mc_id = entity.get_mc_id()
        self.mc_name = None
        if (self.mc_id != None):
            self.mc_id.to_mc(self);
            pass

        if entity.is_hot_swappable():
            if entity.supports_managed_hot_swap():
                hot_swap = "Managed"
            else:
                hot_swap = "Simple"
                pass
        else:
            hot_swap = "No"
            pass
        if (hot_swap != self.hot_swap):
            self.hot_swap = hot_swap
            if (hot_swap != "No"):
                entity.get_hot_swap_state(self)
            else:
                self.hot_swap_state = ''
                pass
            pass

        self.supports_auto_activate = entity.supports_auto_activate_time()
        self.supports_auto_deactivate = entity.supports_auto_deactivate_time()

        # Fill in the various value in the GUI
        self.ui.set_item_text(self.typeitem, self.entity_type)
        self.ui.set_item_text(self.idstringitem, self.id_str)
        self.ui.set_item_text(self.psatitem,
                           str(entity.get_presence_sensor_always_there() != 0))
        if (self.slot_number != None):
            self.ui.set_item_text(self.slotnumitem, str(self.slot_number))
            pass
        self.ui.set_item_text(self.mcitem, self.mc_name)
        self.ui.set_item_text(self.hotswapitem,
                              self.hot_swap + ' ' + self.hot_swap_state)
        return

    def entity_hot_swap_update_cb(self, entity, old_state, new_state, event):
        if (self.destroyed):
            return
        self.hot_swap_state = new_state
        self.ui.set_item_text(self.hotswapitem,
                              self.hot_swap + ' ' + self.hot_swap_state)
        return OpenIPMI.EVENT_NOT_HANDLED
    
    def entity_hot_swap_cb(self, entity, err, state):
        if (self.destroyed):
            return
        if (err):
            _oi_logging.error("Error getting entity hot-swap state: " + str(err))
            return
        self.hot_swap_state = state
        self.ui.set_item_text(self.hotswapitem,
                              self.hot_swap + ' ' + self.hot_swap_state)
        return
    
    def mc_cb(self, mc):
        self.mc_name = mc.get_name()
        return
        
    def entity_iter_entities_cb(self, e1, e2):
        if (self.eeop == "fparent"):
            self.parent_id = e2.get_id()
            self.parent = self.d.find_or_create_entity(e2)
            pass
        elif (self.eeop == "repch"):
            ch_e = self.d.find_entity_byname(e2.get_name())
            if (ch_e):
                ch_e.parent_id = None
                ch_e.Changed(e2)
                pass
            pass
        return

    def entity_iter_sensors_cb(self, entity, sensor):
        self.entity_sensor_update_cb(self.eop, entity, sensor)
        return
    
    def entity_iter_controls_cb(self, entity, control):
        self.entity_control_update_cb(self.eop, entity, control)
        return
    
    def remove(self):
        self.d.entities.pop(self.name)
        self.ui.remove_entity(self)
        self.destroyed = True
        self.d = None
        self.ui = None
        return

    def entity_sensor_update_cb(self, op, entity, sensor):
        if (self.destroyed):
            return
        if (op == "added"):
            if (sensor.get_name() not in self.sensors):
                e = _sensor.Sensor(self, sensor)
                pass
            pass
        elif (op == "deleted"):
            if (sensor.get_name() in self.sensors):
                self.sensors[sensor.get_name()].remove()
                pass
            pass
        return

    def entity_control_update_cb(self, op, entity, control):
        if (self.destroyed):
            return
        if (op == "added"):
            if (control.get_name() not in self.controls):
                e = _control.Control(self, control)
                pass
            pass
        elif (op == "deleted"):
            if (control.get_name() in self.controls):
                self.controls[control.get_name()].remove()
                pass
            pass
        return

    def entity_presence_cb(self, entity, present, event):
        if (self.destroyed):
            return
        if (present):
            self.ui.set_item_active(self.treeroot)
        else:
            self.ui.set_item_inactive(self.treeroot)
            pass
        return

    pass
