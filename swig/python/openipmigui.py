#!/usr/bin/env python

# openipmigui.py
#
# The openipmi GUI startup file
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
        objs = self.domains.values()
        objs.append(self.ui)
        _saveprefs.save(objs, self.preffile)

    def log(self, level, log):
        self.ui.new_log(level + ": " + log);

class DummyLogHandler:
    def __init__(self):
        pass

    def log(self, level, log):
        print level + ": " + log

class IPMIGUI_App(wx.App):
    def __init__(self, mainhandler):
        self.name = "IPMI GUI"
        self.mainhandler = mainhandler
        wx.App.__init__(self);

    def OnInit(self):
        ui = gui.IPMIGUI(self.mainhandler)
        self.mainhandler.SetUI(ui)
    
        self.SetTopWindow(ui)

        OpenIPMI.add_domain_change_handler(self.mainhandler)
        OpenIPMI.set_log_handler(self.mainhandler)

        _domain.RestoreDomains(self.mainhandler)

        return True

def ipmithread():
    while True:
        OpenIPMI.wait_io(1000)
        pass
    return

def run():
    if ((wx.VERSION[0] < 2)
        or ((wx.VERSION[0] == 2) and (wx.VERSION[1] < 4))
        or ((wx.VERSION[0] == 2) and (wx.VERSION[1] == 4)
            and (wx.VERSION[2] < 2))):
        print "Error: wxPython version must be 2.4.2 or greater"
        return

    OpenIPMI.enable_debug_malloc()
    OpenIPMI.init()
    #OpenIPMI.enable_debug_rawmsg()

    preffile = os.path.join(os.environ['HOME'], '.openipmigui.startup')
    _saveprefs.restore(preffile)
    mainhandler = DomainHandler(preffile)

    OpenIPMI.add_domain_change_handler(_domain.DomainWatcher(mainhandler))

    app = IPMIGUI_App(mainhandler)

    if ((wx.VERSION[0] == 2) and (wx.VERSION[1] <= 4)):
        # Version 2.4 of wxPython uses glib1.2, but OpenIPMI usually
        # uses 2.0 if available.  That means we need two different
        # event loops :(.
        import thread
        thread.start_new_thread(ipmithread, ())
        pass
    
    app.MainLoop()
    OpenIPMI.set_log_handler(DummyLogHandler())
    OpenIPMI.shutdown_everything()


#def trace(frame, event, arg):
#    print (event + ": " + frame.f_code.co_name +
#           "(" + frame.f_code.co_filename + ":" + str(frame.f_lineno) + ")")
#    return trace

if __name__ == "__main__":
    #import sys
    #sys.settrace(trace)
    run()
