import OpenIPMI

class Sensor:
    def __init__(self, e, sensor):
        self.e = e
        self.name = sensor.get_name()
        self.sensor_id = sensor.get_id()
        self.ui = e.ui
        ui = self.ui
        ui.add_sensor(self.e, self)
        self.valueitem = ui.append_item(self, "Value", None)
        sensor.get_value(self)

    def __str__(self):
        return self.name

    def remove(self):
        self.e.sensors.pop(self.name)
        self.ui.remove_sensor(self)

    def threshold_reading_cb(self, sensor, err, raw_set, raw, value_set,
                             value, states):
        if (err):
            self.ui.set_item_text(self.valueitem, "Value", None)
            return
        v = ""
        if (value_set):
            v = v + str(value)
        if (raw_set):
            v = v + "(" + str(raw) + ")"
        v = v + ": " + states
        self.ui.set_item_text(self.valueitem, "Value", v)
        
    def discrete_states_cb(self, sensor, err, states):
        if (err):
            self.ui.set_item_text(self.valueitem, "Value", None)
            return
        self.ui.set_item_text(self.valueitem, "Value", states)
        
