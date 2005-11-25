
import OpenIPMI

class Control:
    def __init__(self, e, control):
        self.e = e
        self.name = control.get_name()
        self.control_id = control.get_id()
        self.ui = e.ui;
        self.ui.add_control(self.e, self)

    def __str__(self):
        return self.name

    def remove(self):
        self.e.controls.pop(self.name)
        self.ui.remove_control(self)

