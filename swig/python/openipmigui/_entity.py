
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
        self.ui.add_entity(self.d, self)
        self.sensors = { }
        self.controls = { }

    def __str__(self):
        return self.name

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

