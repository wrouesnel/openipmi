#!/usr/bin/python

# sample
#
# A sample file that uses most of the python/OpenIPMI interface
#
# Author: MontaVista Software, Inc.
#         Corey Minyard <minyard@mvista.com>
#         source@mvista.com
#
# Copyright 2010 MontaVista Software Inc.
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

import sys
import OpenIPMI

# Used to count things waiting for shutdown
stop_count = 1
main_handler = None
stop_list = {}

class MC_Nameget:
    def __init__(self):
        self.name = None
        pass

    def mc_cb(self, mc):
	self.name = mc.get_name()
        pass
    pass

threshold_list = ("ln", "lc", "lr", "un", "uc", "ur")
low_high = ("l", "h")
act_deact = ("a", "d")

class Handlers:
    def __init__(self, name):
        self.name = name
        return

    def event_cb(self, domain, event):
	mcid = event.get_mc_id()

	name = MC_Nameget()
	mcid.to_mc(name)
        name = name.name
	data = event.get_data()

	print ("Got event: " + name + " " + str(event.get_record_id()) +
               " " + str(event.get_type()) + " " + str(event.get_timestamp()))
        datastr = ""
        for b in data:
            datastr += " %2.2x" % b
            pass
	print "  Data:" + datastr
        return

    def entity_presence_cb(self, entity, present, event):
	print "Entity " + entity.get_name() + " presence is " + str(present)

        if event:
	    self.event_cb(entity.get_domain(), event)
            pass
        return

    def threshold_event_cb(self, sensor, event_spec, raw_set, raw,
                           value_set, value, event):
	print "Sensor " + sensor.get_name() + " got event " + event_spec
        if raw_set:
	    print "  raw value = " + str(raw)
            pass
        if value_set:
	    print "  value = " + str(value)
            pass
        if event:
            entity = sensor.get_entity()
	    self.event_cb(entity.get_domain(), event)
            pass
        return

    def discrete_event_cb(self, sensor, event_spec, severity, old_severity,
                          event):
	print "Sensor " + sensor.get_name() + " got event " + event_spec
	print "  severity = " + str(severity) + " was = " + str(old_severity)
        if event:
            entity = sensor.get_entity()
	    self.event_cb(entity.get_domain(), event)
            pass
        return

    def entity_sensor_update_cb(self, op, entity, sensor):
	print op + " sensor " + sensor.get_name()
        if ((op == "added") or (op == "changed")):
	    print "  lun = " + str(sensor.get_lun())
	    print "  num = " + str(sensor.get_num())
	    print "  sensor_type_string = " + sensor.get_sensor_type_string()
	    print "  sensor_type = " + str(sensor.get_sensor_type())
	    print("  event_reading_type_string = " +
                  sensor.get_event_reading_type_string())
	    print("  event_reading_type = "
                  + str(sensor.get_event_reading_type()))
	    print "  entity_id = " + str(sensor.get_entity_id())
	    print "  entity_instance = " + str(sensor.get_entity_instance())
	    print("  sensor_init_scanning = " +
                   str(sensor.get_sensor_init_scanning()))
	    print("  sensor_init_events = "
                  + str(sensor.get_sensor_init_events()))
	    print("  sensor_init_thresholds = " +
                  str(sensor.get_sensor_init_thresholds()))
	    print("  sensor_init_hysteresis = " +
                  str(sensor.get_sensor_init_hysteresis()))
	    print("  sensor_init_type = " +
                  str(sensor.get_sensor_init_type()))
	    print("  sensor_init_pu_events = " +
                  str(sensor.get_sensor_init_pu_events()))
	    print("  sensor_init_pu_scanning = " +
                  str(sensor.get_sensor_init_pu_scanning()))
	    print("  ignore_if_no_entity = " +
                  str(sensor.get_ignore_if_no_entity()))
	    print("  supports_auto_rearm = " +
                  str(sensor.get_supports_auto_rearm()))
	    print "  event_support = " + str(sensor.get_event_support())
	    print "  sensor_direction = " + str(sensor.get_sensor_direction())
	    print "  oem1 = " + str(sensor.get_oem1())
	    print "  sensor_id = " + sensor.get_sensor_id()

	    if (sensor.get_event_reading_type()
                == OpenIPMI.EVENT_READING_TYPE_THRESHOLD):
		print "  rate_unit_string = " + sensor.get_rate_unit_string()
		print "  rate_unit = " + str(sensor.get_rate_unit())
		print("  base_unit_string = " +
                      sensor.get_base_unit_string())
		print "  base_unit = " + str(sensor.get_base_unit())
		print("  modifier_unit_string = " +
		       sensor.get_modifier_unit_string())
		print "  modifier_unit = " + str(sensor.get_modifier_unit())
		print("  modifier_unit_use = " +
                      str(sensor.get_modifier_unit_use()))
		print "  percentage = " + str(sensor.get_percentage())
		print("  threshold_access = " +
		      str(sensor.get_threshold_access()))
		print("  hysteresis_support = " +
		      str(sensor.get_hysteresis_support()))

                val = [ 0.0 ]
                if sensor.get_normal_min_specified():
		    rv = sensor.get_normal_min(val)
                    if rv:
                        print "***Error getting normal min: " + rv
		    else:
			print "  normal_min = " + str(val[0])
                        pass
                    pass

		if sensor.get_normal_max_specified():
		    rv = sensor.get_normal_max(val)
                    if rv:
                        print "***Error getting normal max: " + rv
		    else:
			print "  normal_max = " + str(val[0])
                        pass
                    pass

                if sensor.get_nominal_reading_specified():
		    rv = sensor.get_nominal_reading(val)
                    if rv:
			print "***Error getting nominal reading: " + str(rv)
		    else:
			print "  nominal_reading = " + str(val[0])
                        pass
                    pass
                
		rv = sensor.get_sensor_max(val)
                if rv:
		    print "***Error getting sensor max: " + str(rv)
		else:
		    print "  sensor_max = " + str(val[0])
                    pass
                pass

		rv = sensor.get_sensor_min(val)
                if rv:
		    print "***Error getting sensor min: " + str(rv)
		else:
		    print "  sensor_min = " + str(val[0])
                    pass
                pass

		rv = sensor.get_tolerance(128, val)
                if rv == 0:
		    print "  tolerance at 128 is " + str(val[0])
                    pass

		rv = sensor.get_accuracy(128, val)
                if rv == 0:
		    print "  accuracy at 128 is " + str(val[0])
                    pass

                for i in threshold_list:
		    supported = [ 0 ]
		    settable = [ 0 ]
		    readable = [ 0 ]

		    rv = sensor.threshold_reading_supported(i, supported)
                    if rv:
			print("***Error getting supported for threshold %s: %s"
                              % (i, str(rv)))
                        pass
                    supported = supported[0]

                    if not supported:
			continue

		    tstr = "  Threshold '" + i + "' supported:"

		    rv = sensor.threshold_settable(i, settable)
                    if rv:
			print("***Error getting settable for threshold %s: %s"
                              % (i, str(rv)))
                        pass
                    settable = settable[0]
                    if settable:
			tstr += " settable"
                        pass

		    rv = sensor.threshold_readable(i, readable)
                    if rv:
			print("***Error getting readable for threshold %s: %s"
                              % (i, str(rv)))
                        pass
                    readable = readable[0]
                    if readable:
			tstr += " readable"
                        pass
		    print tstr

		    tstr = "    Supports events:"
                    for j in low_high:
                        for k in act_deact:
			    e = i + j + k
			    s = [ 0 ]
			    rv = sensor.threshold_event_supported(e, s)
                            if rv:
				print ("***Error getting ev support for event "
                                       + e + ": " + str(rv))
			    elif s[0]:
				tstr += " " + e
                                pass
                            pass
                        pass
		    print tstr
                    pass
                pass
            else:
                for i in range(0, 14):
		    a_supported = [ 0 ]
		    d_supported = [ 0 ]
		    readable = [ 0 ]

		    rv = sensor.discrete_event_readable(i, readable)
                    if rv:
			print ("***Error getting readable for offset %d: %s"
                               % (i, str(rv)))
                        pass
                    readable = readable[0]
                    
		    rv = sensor.discrete_event_supported(str(i) + "a",
                                                         a_supported)
                    if rv:
			print ("***Error getting a supported for offset %d: %s"
                               % (i, str(rv)))
                        pass
                    a_supported = a_supported[0]

		    rv = sensor.discrete_event_supported(str(i) + "d",
                                                         d_supported)
                    if rv:
			print ("***Error getting d supported for offset %s: %s"
                               % (i, str(rv)))
                        pass
                    d_supported = d_supported[0]

                    if readable or a_supported or d_supported:
			s = sensor.reading_name_string(i)
			tstr = "  Offset %d (%s) supported:" % (i, s)

                        if readable:
			    tstr += " readable"
                            pass
                        if a_supported:
			    tstr += " assert"
                            pass
                        if d_supported:
			    tstr += " deassert"
                            pass
                        print tstr
                        pass
                    pass
                pass
	    
            if op == "added":
		rv = sensor.add_event_handler(self)
                if rv:
		    print "***Unable to add event handler: " + str(rv)
                    pass
                pass
            pass
        elif op == "deleted":
            rv = sensor.remove_event_handler(self)
            if rv:
		print "***Unable to remove event handler: " + str(rv)
                pass
            pass
        return

    def control_get_val_cb(self, control, err, vals):
	tstr = "Control %s err = %s, values = " % (control.get_name(),str(err))
        for v in vals:
            tstr += " %d" % v
            pass
	print tstr
        return

    def control_get_light_cb(self, control, err, vals):
	print("Control %s err = %s, light value = %s"
              % (control.get_name(), str(err), vals))
        return

    def control_get_id_cb(self, control, err, val):
	tstr = ("Control %s err = %s, id value = "
                % (control.get_name(), str(err)))
        for v in vals:
            tstr += " %2.2x" % v
            pass
        print tstr
        return

    def control_event_val_cb(self, control, event, num, valids, vals):
	tstr = "Control " + control.get_name() + " event, values ="
        for i in range(0, len(valids)):
            if valids[i]:
                v = "valid"
            else:
                v = "invalid"
                pass
            tstr += " (%s, %d)" % (v, vals[i])
            pass
        print tstr
        return

    def entity_control_update_cb(self, op, entity, control):
	use_setting = 0

	print op + " control " + control.get_name()
        if ((op == "added") or (op == "changed")):
	    t = control.get_type()
	    print "  type = " + str(t)
	    print "  entity_id = " + str(control.get_entity_id())
	    print "  entity_instance = " + str(control.get_entity_instance())
	    print "  settable = " + str(control.is_settable())
	    print "  readable = " + str(control.is_readable())
	    print("  ignore_if_no_entity = " +
		  str(control.get_ignore_if_no_entity()))
	    print "  control_id = " + str(control.get_control_id())
	    print "  has_events = " + str(control.has_events())
	    num_vals = control.get_num_vals()
	    print "  num_vals = " + str(num_vals)

            if t == OpenIPMI.CONTROL_LIGHT:
		use_setting = control.light_set_with_setting()
                pass

	    if use_setting:
		print "  light controlled with setting"
		tstr = "  Colors: "
                for i in range(0, OpenIPMI.CONTROL_NUM_COLORS):
                    if (control.light_is_color_supported(i)):
			tstr += " " + OpenIPMI.color_string(i) + ("(%d)" % i)
                        pass
                    pass
		print tstr
		print("  light_has_local_control = " +
		      str(control.light_has_local_control()))
		rv = control.ipmi_control_get_light(self)
                if rv:
		    print "***Error getting light: " + str(rv)
                    pass
                pass
	    elif t == OpenIPMI.CONTROL_IDENTIFIER:
		print("  identifier_get_max_length = " +
		      str(control.identifier_get_max_length()))
		rv = control.identifier_get_val(self)
                if rv:
		    print "***Error getting control id: " + str(rv)
                    pass
                pas
            elif t == OpenIPMI.CONTROL_LIGHT:
                for i in range(0, num_vals) :
                    n = control.get_num_light_values(i)
                    print "  Light %d" % i
                    for j in range (0, n):
                        print "    Value %d" % j
                        o = control.get_num_light_transitions(i, j)
                        for k in range (0, o):
                            tstr = "    Transition %d:" & k
                            v = control.get_light_color(i, j, k)
                            tstr += " " + OpenIPMI.color_string(v)
                            v = control.get_light_color_time(i, j, k)
                            tstr += " time(" + str(v) + ")"
                            pass
                        pass
                    pass
                pass

            if op == "added":
		rv = control.add_event_handler(self)
                if rv:
		    print "***Error adding control event handler: " + str(rv)
                    pass
                pass
            pass
        elif op == "deleted":
	    rv = control.remove_event_handler(self)
            if rv:
		print "***Error removing control event handler: " + str(rv)
                pass
            pass
        return
    
    def print_multirecord(self, node, indent):
	name = [ "" ]
	t = [ "" ]
	value = [ "" ]
	sub_node = [ None ]
    
	i = 0
        while True:
	    rv = node.get_field(i, name, t, value, sub_node)
            if rv == OpenIPMI.einval:
		return
	    i += 1
            if rv:
		continue

	    print "%s%s, %s, %s" % (indent, name[0], t[0], value[0])
            if t == "subnode":
		self.print_multirecord(subnode[0], indent + "  ")
                pass
            pass
        return

    def entity_fru_update_cb(self, op, entity, fru):
	print op + " fru for " + entity.get_name()
        if ((op == "added") or (op == "changed")):
	    i = fru.str_to_index("internal_use_version")
            if i == -1:
		print "*** FRU string 'internal_use_version' was invalid"
	    else:
		print "  internal_use_version index is %d" % i
                pass
	    i = fru.str_to_index("blah blah")
            if i != -1:
		print "*** FRU string 'blah blah' was valid"
                pass

	    i = 0
	    j = [ 0 ]
	    k = j[0]
	    rv = fru.get(i, j)
            while rv:
                v = rv.split(" ", 2)
                if len(v) > 2:
                    name = v[0]
                    t = v[1]
		    print "  %s, %s, %s" % (name, t, v[2])
                    pass
                if j[0] != k:
                    if j[0] == -1:
			i += 1
			j = [ 0 ]
                        pass
                    pass
                else:
		    i += 1
		    j = [ 0 ]
                    pass

		k = j[0]
		rv = fru.get(i, j)
                pass
	    j = fru.get_num_multi_records()
	    print "%d multirecords" % j
            for i in range(0, j):
		name = [ "" ]
		sub_node = [ None ]
		rv = fru.multi_record_get_root_node(i, name, sub_node)
                if rv:
		    print "Multirecord %d has no decoder" % i
		    continue
		print "Multirecord %d (%s)" % (i, name[0])
		self.print_multirecord(sub_node[0], "  ")
                pass
            pass
        return

    def entity_hot_swap_update_cb(self, entity, old_state, new_state, event):
	print("Hot swap change for %s was %s now %s"
              % (entity.get_name(), old_state, new_state))
        if event:
	    self.event_cb(entity.get_domain(), event)
            pass
        return

    def entity_update_cb(self, op, domain, entity):
	print op + " entity " + entity.get_name()
        if ((op == "added") or (op == "changed")):
	    print "  type = " + entity.get_type()
	    print "  is_fru = " + str(entity.is_fru())
	    print "  entity_id = " + str(entity.get_entity_id())
	    print "  entity_instance = " + str(entity.get_entity_instance())
	    print("  device_channel = " +
		  str(entity.get_entity_device_channel()))
	    print("  device_address = " +
		  str(entity.get_entity_device_address()))
	    print("  presence_sensor_always_there = " +
		   str(entity.get_presence_sensor_always_there()))
	    print "  channel = " + str(entity.get_channel())
	    print "  lun = " + str(entity.get_lun())
	    print "  oem = " + str(entity.get_oem())
	    print "  access_address = " + str(entity.get_access_address())
	    print "  private_bus_id = " + str(entity.get_private_bus_id())
	    print "  device_type = " + str(entity.get_device_type())
	    print "  device_modifier = " + str(entity.get_device_modifier())
	    print "  slave_address = " + str(entity.get_slave_address())
	    print "  is_logical_fru = " + str(entity.get_is_logical_fru())
	    print "  fru_device_id = " + str(entity.get_fru_device_id())
	    print("  ACPI_system_power_notify_required = " +
		  str(entity.get_ACPI_system_power_notify_required()))
	    print("  ACPI_device_power_notify_required = " +
		  str(entity.get_ACPI_device_power_notify_required()))
	    print("  controller_logs_init_agent_errors = " +
		  str(entity.get_controller_logs_init_agent_errors()))
	    print("  log_init_agent_errors_accessing = " +
		  str(entity.get_log_init_agent_errors_accessing()))
	    print "  global_init = " + str(entity.get_global_init())
	    print "  chassis_device = " + str(entity.get_chassis_device())
	    print "  bridge = " + str(entity.get_bridge())
	    print("  IPMB_event_generator = " +
		  str(entity.get_IPMB_event_generator()))
	    print("  IPMB_event_receiver = " +
		  str(entity.get_IPMB_event_receiver()))
	    print("  FRU_inventory_device = " +
		  str(entity.get_FRU_inventory_device()))
	    print "  SEL_device = " + str(entity.get_SEL_device())
	    print("  SDR_repository_device = " +
		  str(entity.get_SDR_repository_device()))
	    print "  sensor_device = " + str(entity.get_sensor_device())
	    print "  address_span = " + str(entity.get_address_span())
	    print "  dlr_id = " + str(entity.get_dlr_id())
	    print "  present = " + str(entity.is_present())
	    print "  hot_swappable = " + str(entity.is_hot_swappable())
            if op == "added":
		rv = entity.add_presence_handler(self)
                if rv:
		    print "***Unable to add presence handler: " + str(rv)
                    pass
		rv = entity.add_sensor_update_handler(self)
                if rv:
		    print "***Unable to add sensor update handler: " + str(rv)
                    pass
		rv = entity.add_control_update_handler(self)
                if rv:
		    print "***Unable to add control update handler: " + str(rv)
                    pass
		rv = entity.add_hot_swap_handler(self)
                if rv:
		    print "***Unable to add hot-swap handler: " + str(rv)
                    pass
		rv = entity.add_fru_update_handler(self)
                if rv:
		    print "***Unable to add fru handler: " + str(rv)
                    pass
                pass
            pass
        elif op == "deleted":
	    rv = entity.remove_presence_handler(self)
	    if rv:
                print "***Unable to remove presence handler: " + str(rv)
                pass
	    rv = entity.remove_sensor_update_handler(self)
	    if rv:
                print "***Unable to remove sensor update handler: " + str(rv)
                pass
	    rv = entity.remove_control_update_handler(self)
	    if rv:
                print "***Unable to remove control update handler: " + str(rv)
                pass
	    rv = entity.remove_hot_swap_handler(self)
            if rv:
		print "***Unable to remove hot-swap handler: " + str(rv)
                pass
	    rv = entity.remove_fru_update_handler(self)
            if rv:
		print "***Unable to add fru handler: " + str(rv)
                pass
            pass
        return

    def mc_active_cb(self, mc, active):
	print "MC " + mc.get_name() + " active set to " + str(active)
        return

    def mc_events_enable_cb(self, mc, err):
        global stop_count, stop_list
	print "Events enabled for " + mc.get_name() + " err = " + str(err)
        stop_list["mc_set_events_enable"] = 0
	stop_count -= 1
        print str(stop_list)
        if stop_count == 0:
            domain = mc.get_domain()
	    domain.close(main_handler)
            pass
        return

    def mc_reread_sel_cb(self, mc, err):
        global stop_count, stop_list
	domain = mc.get_domain()

	print "SEL reread for " + mc.get_name() + " err = " + str(err)
        stop_list["mc_reread_sel"] = 0
	stop_count -= 1
        print str(stop_list)
        if stop_count == 0:
	    domain.close(main_handler)
            pass
        return

    def mc_reread_sensors_cb(self, mc, err):
        global stop_count, stop_list
	domain = mc.get_domain()

	print "Sensors reread for " + mc.get_name() + " err = " + str(err)
        stop_list["mc_reread_sensors"] = 0
	stop_count -= 1
        print str(stop_list)
        if stop_count == 0:
	    domain.close(main_handler)
            pass
        return

    def mc_get_sel_time_cb(self, mc, err, time):
        global stop_count, stop_list
	domain = mc.get_domain()

	print("SEL time for " + mc.get_name() + " is " + str(time) + ", err = "
              + str(err))
        stop_list["mc_get_sel_time"] = 0
	stop_count -= 1
        print str(stop_list)
        if stop_count == 0:
	    domain.close(main_handler)
            pass
        return

    def mc_update_cb(self, op, domain, mc):
        global stop_count, stop_list
	print op + " MC " + mc.get_name()
        if ((op == "added") or (op == "changed")):
	    print("  provides_device_sdrs = " +
		  str(mc.provides_device_sdrs()))
	    print "  device_available = " + str(mc.device_available())
	    print "  chassis_support = " + str(mc.chassis_support())
	    print "  bridge_support = " + str(mc.bridge_support())
	    print("  ipmb_event_generator_support = " +
		  str(mc.ipmb_event_generator_support()))
	    print("  ipmb_event_receiver_support = " +
                  str(mc.ipmb_event_receiver_support()))
	    print("  fru_inventory_support = " +
		  str(mc.fru_inventory_support()))
	    print("  sel_device_support = " +
		  str(mc.sel_device_support()))
	    print("  sdr_repository_support = " +
		  str(mc.sdr_repository_support()))
	    print("  sensor_device_support = " +
		  str(mc.sensor_device_support()))
	    print "  device_id = " + str(mc.device_id())
	    print "  device_revision = " + str(mc.device_revision())
	    print "  major_fw_revision = " + str(mc.major_fw_revision())
	    print "  minor_fw_revision = " + str(mc.minor_fw_revision())
	    print "  major_version = " + str(mc.major_version())
	    print "  minor_version = " + str(mc.minor_version())
	    print "  manufacturer_id = " + str(mc.manufacturer_id())
	    print "  product_id = " + str(mc.product_id())
	    print "  aux_fw_revision = " + str(mc.aux_fw_revision())
	    print "  is_active = " + str(mc.is_active())
	    print "  get_events_enable = " + str(mc.get_events_enable())
	    print "  sel_count = " + str(mc.sel_count())
	    print "  sel_entries_used = " + str(mc.sel_entries_used())
	    print("  sel_get_major_version = " +
		  str(mc.sel_get_major_version()))
	    print("  sel_get_minor_version = " +
		  str(mc.sel_get_minor_version()))
	    print("  sel_get_num_entries = " +
		  str(mc.sel_get_num_entries()))
	    print "  sel_get_free_bytes = " + str(mc.sel_get_free_bytes())
	    print "  sel_get_overflow = " + str(mc.sel_get_overflow())
	    print("  sel_get_supports_delete_sel = " +
		  str(mc.sel_get_supports_delete_sel()))
	    print("  sel_get_supports_partial_add_sel = " +
		  str(mc.sel_get_supports_partial_add_sel()))
	    print("  sel_get_supports_reserve_sel = " +
		  str(mc.sel_get_supports_reserve_sel()))
	    print("  sel_get_supports_get_sel_allocation = " +
		  str(mc.sel_get_supports_get_sel_allocation()))
	    print("  sel_get_last_addition_timestamp = " +
		  str(mc.sel_get_last_addition_timestamp()))
	    print("  get_sel_rescan_time = " +
		  str(mc.get_sel_rescan_time()))

	    stop_count += 2
            stop_list["mc_set_events_enable"] = 1
	    rv = mc.set_events_enable(1, self)
	    if rv:
		print "***Error enabling MC events: " + str(rv)
                stop_count -= 1
                pass

	    stop_count += 1
            stop_list["mc_reread_sensors"] = 1
	    rv = mc.reread_sensors(self)
            if rv:
		print "***Error rereading MC sensors: " + str(rv)
                stop_list["mc_reread_sensors"] = 0
		stop_count -= 1
                pass

	    mc.set_sel_rescan_time(5)

	    stop_count += 1
            stop_list["mc_reread_sel"] = 1
	    rv = mc.reread_sel(self)
            if rv:
		print "***Error rereading MC SEL: " + str(rv)
                stop_list["mc_reread_sel"] = 0
		stop_count -= 1
                pass

	    stop_count += 1
            stop_list["mc_get_sel_time"] = 1
	    rv = mc.get_current_sel_time(self)
            if rv:
		print "***Error getting current MC SEL time: " + str(rv)
		stop_count -= 1
                pass

	    # Stop count for this incremented at first.
            stop_list["mc_send_command"] = 1
	    rv = mc.send_command(0, 10, 0x43,
                                 [ 0, 0, 0, 0, 0, 0xff ], self)
            if rv:
		print "***Unable to send mc command: " + str(rv)
		stop_count -= 1
                pass

            if op == "added":
		rv = mc.add_active_handler(self)
                if rv:
		    print "***Unable to add active handler: " + str(rv)
                    pass
                pass
            pass
        elif op == "deleted":
            rv = mc.remove_active_handler(self)
            if rv:
                print "***Unable to remove active handler: " + str(rv)
                pass
            pass
        return

    def domain_addr_cmd_cb(self, domain, addr, lun, netfn, cmd, data):
	print "Got message from " + domain.get_name()
	print " addr = " + addr
	print " lun=%d, netfn=%d, cmd=%d" % (lun, netfn, cmd)
	tstr = " data:"
        for b in data:
	    tstr += " %2.2x" % b
            pass
	print tstr
        return

    def mc_cmd_cb(self, mc, netfn, cmd, data):
        global stop_count, stop_list
	print "Got message from " + mc.get_name()
	print " netfn=%d, cmd=%d" % (netfn, cmd)
	tstr = " data:"
        for b in data:
	    tstr += " %2.2x" % b
            pass
	print tstr
        stop_list["mc_send_command"] = 0
	stop_count -= 1
        print str(stop_list)
        if stop_count == 0:
	    mc.get_domain().close(main_handler)
            pass
        return

    def conn_change_cb(self, domain, err, conn_num, port_num, still_connected):
	print "Open done (%s): %s" % (self.name, domain.get_name())
        if self.name == "hello":
	    i = Handlers("goodbye")
	    rv = domain.add_connect_change_handler(i)
            if rv:
		print "Unable to add connect change handler: " + str(rv)
                pass
	    rv = domain.remove_connect_change_handler(self)
            if rv:
		print "Unable to remove connect change handler: " + str(rv)
                pass

	    rv = domain.add_entity_update_handler(i)
            if rv:
		print "Unable to add entity updated handler: " + str(rv)
                pass
	    rv = domain.add_mc_update_handler(i)
            if rv:
		print "Unable to add mc updated handler: " + str(rv)
                pass

	    rv = domain.send_command_addr("smi 15 ", 0, 6, 1, [], self)
            if rv:
		print "Unable to send domain command (1): " + str(rv)
                pass

	    rv = domain.add_event_handler(self)
            if rv:
		print "Unable to add event handler: " + str(rv)
                pass
	else:
	    rv = domain.send_command_addr("ipmb 0 32", 0, 10, 0x43,
                                          [ 0, 0, 0, 0, 0, 0xff ], self)
            if rv:
		print "Unable to send domain command (2): " + str(rv)
                pass
            pass
        return

    def domain_up_cb(self, domain):
        global stop_count, stop_list
	print "Domain up: " + domain.get_name()
	print "  type = " + domain.get_type()
	print "  sel_rescan_type = " + str(domain.get_sel_rescan_time())
	print "  ipmb_rescan_type = " + str(domain.get_ipmb_rescan_time())
	domain.set_sel_rescan_time(5)
	domain.set_ipmb_rescan_time(20)
	domain.iterate_entities(self)
	domain.iterate_mcs(self)

	event = domain.first_event()
        while event:
	    self.event_cb(domain, event)
	    event = domain.next_event(event)
            pass

	# stop count is incremented at domain startup, don't need another.
	stop_count += 1
        stop_list["mc_ipmb_mc_scan"] = 1
	rv = domain.start_ipmb_mc_scan(0, 0x20, 0x20, self)
        if rv:
	    print "Error starting IPMB scan: " + str(rv)
	    stop_count -= 1
            pass

        stop_list["domain_reread_sels"] = 1
	rv = domain.reread_sels(self)
        if rv:
	    print "Error starting IPMB scan: " + str(rv)
	    stop_count -= 1
            pass
        return

    def domain_reread_sels_cb(self, domain, err):
        global stop_count, stop_list
	print "SEL rescan done for " + domain.get_name() + " err=" + str(err)
        stop_list["domain_reread_sels"] = 0
	stop_count -= 1
        print str(stop_list)
        if stop_count == 0:
	    domain.close(main_handler)
            pass
        return

    def domain_close_done_cb(self):
	self.name = "done"
        return

    def domain_ipmb_mc_scan_cb(self, domain, err):
        global stop_count, stop_list
	print "IPMB scan done for " + domain.get_name() + " err=" + str(err)
        stop_list["mc_ipmb_mc_scan"] = 0
	stop_count -= 1
        print str(stop_list)
        if stop_count == 0:
	    domain.close(main_handler)
            pass
        return

    def entity_iter_entities_cb(self, relative, entity):
	print "    " + entity.get_name()
        return

    def entity_iter_sensors_cb(self, entity, sensor):
	print "Sensor: " + sensor.get_name()

    def entity_iter_controls_cb(self, entity, control):
	print "Control: " + control.get_name()

    def domain_iter_entity_cb(self, domain, entity):
	print "Entity: " + entity.get_name()
        if entity.is_child():
	    print "  Parents:"
	    entity.iterate_parents(self)
            pass
        if entity.is_parent():
	    print "  Children:"
	    entity.iterate_children(self)
            pass

	entity.iterate_sensors(self)
	entity.iterate_controls(self)
        return

    def domain_iter_mc_cb(self, domain, mc):
	print "MC: " + mc.get_name()

	event = mc.first_event()
        while event:
	    self.event_cb(mc.get_domain(), event)
	    event = mc.next_event(event)
            pass
        return

    def log(self, level, log):
	print level + ": " + log
        return

    pass

OpenIPMI.enable_debug_malloc()
OpenIPMI.init_posix()

main_handler = Handlers("hello")

OpenIPMI.set_log_handler(main_handler)

a = OpenIPMI.open_domain2("test", sys.argv[1:], main_handler, main_handler)
if not a:
    print "open failed"
    sys.exit(1)
    pass
del a

while main_handler.name != "done":
    OpenIPMI.wait_io(1000)
    pass

class DummyLogHandler:
    def __init__(self):
        pass

    def log(self, level, log):
        sys.stderr.write(level + ": " + log + "\n")

OpenIPMI.set_log_handler(DummyLogHandler())
OpenIPMI.shutdown_everything()
print "done"
sys.exit(0)

