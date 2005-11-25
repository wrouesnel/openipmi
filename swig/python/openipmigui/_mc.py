import OpenIPMI

class MC:
    def __init__(self, d, mc):
        self.d = d
        self.name = mc.get_name()
        d.mcs[self.name] = self
        self.ui = d.ui;
        self.ui.add_mc(self.d, self)

    def remove(self):
        self.d.mcs.pop(self.name)
        self.ui.remove_mc(self)


