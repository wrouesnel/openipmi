#!/usr/bin/env python

#
# This is a GUI interface to the OpenIPMI library.
#
# Naming Conventions:
#
#  The following names are used universally throughout this program.
#  Note that you have two versions of each object, the Python object
#  (class is defined in this program) and the OpenIPMI version of the
#  object (defined by the OpenIPMI library).
#
#  domain - OpenIPMI.ipmi_domain_t
#  domain_id - OpenIPMI.ipmi_domain_id_t
#  entity - OpenIPMI.ipmi_entity_t
#  entity_id - OpenIPMI.ipmi_entity_id_t
#  mc - OpenIPMI.ipmi_mc_t
#  mc_id - OpenIPMI.ipmi_mc_id_t
#  sensor - OpenIPMI.ipmi_sensor_t
#  sensor_id - OpenIPMI.ipmi_sensor_id_t
#  control - OpenIPMI.ipmi_control_t
#  control_id - OpenIPMI.ipmi_control_id_t
#
#  d - Domain
#  e - Entity
#  m - MC
#  s - Sensor
#  c - Control

import os
import wx
import OpenIPMI
from openipmigui import _domain
from openipmigui import gui
from openipmigui import _saveprefs


class DomainHandler:
    def __init__(self, preffile):
        self.domains = { };
        self.preffile = preffile

    def domain_change_cb(self, op, domain):
        if (op == "added"):
            self.domains[domain.get_name()].connected(domain)
        elif (op == "removed"):
            self.domains[domain.get_name()].remove()

    def SetUI(self, ui):
        self.ui = ui;

    def savePrefs(self):
        _saveprefs.save(self.domains.itervalues(), preffile)

    def log(self, level, log):
        self.ui.new_log(level + ": " + log);

class DummyLogHandler:
    def __init__(self):
        pass

    def log(self, level, log):
        print level + ": " + log

class IPMIGUI_App(wx.App):
    def __init__(self):
        self.name = "IPMI GUI"
        wx.App.__init__(self);

if __name__ == "__main__":
    OpenIPMI.enable_debug_malloc()
    OpenIPMI.init()
#    OpenIPMI.enable_debug_msg()

    app = IPMIGUI_App()
    
    preffile = os.path.join(os.environ['HOME'], '.ipmigui.startup')

    mainhandler = DomainHandler(preffile)

    ui = gui.IPMIGUI(mainhandler)
    mainhandler.SetUI(ui)
    
    app.SetTopWindow(ui)

    OpenIPMI.add_domain_change_handler(mainhandler)
    OpenIPMI.set_log_handler(mainhandler)

    _saveprefs.restore(preffile, mainhandler)
    
    app.MainLoop()
    OpenIPMI.set_log_handler(DummyLogHandler())
    OpenIPMI.shutdown_everything()
