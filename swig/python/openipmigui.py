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
import Tix
import sys
import OpenIPMI
from openipmigui import _domain
from openipmigui import gui
from openipmigui import _saveprefs
from openipmigui import gui_cmdwin

# Used to enable internal debug output
verbosity = 0

#
# Nasty thread support stuff.
#
# If python is threaded but TCL is not, we have ugliness to deal with.
# In this case, the _tkinter code has a tcl_lock that is claimed
# whenever it enters TCL code, including the event loop.  If we run
# OpenIPMI events inside the TCL event loop, it will call directly
# into the OpenIPMI calls and bypass _tkinter, leaving the lock held.
# Inside OpenIPMI, it might call back to the python code which can
# then do a TCL call, which will try to claim tcl_lock and deadlock.
#
# We fix this in this case by having a separate thread
# (openipmi_driver() below) run OpenIPMI events, and not in the TCL
# event loop.
#
# If both python and TCL are threaded, the tcl_lock is not used and
# everything is fine with a single thread.  If python is not threaded,
# then threads don't matter.  In those cases we use the TCL event loop
# for everything.
#
# See the _tkinter.c file in the python distribution for more details.
#
shutdown_thread = False
def openipmi_driver():
    while (not shutdown_thread):
        OpenIPMI.wait_io(1000)
        pass
    return

class TopHandler(Tix.Tk):
    def __init__(self, preffile, log_file, histfile):

        Tix.Tk.__init__(self)
        
        self.domains = { };
        self.preffile = preffile
        self.log_file = log_file
        self.histfile = histfile
        return

    def domain_change_cb(self, op, domain):
        if (op == "added"):
            self.domains[domain.get_name()].connected(domain)
        elif (op == "removed"):
            self.domains[domain.get_name()].remove()
            pass
        return

    def SetUI(self, ui):
        self.ui = ui;
        return

    def savePrefs(self):
        objs = self.domains.values()
        objs.append(self.ui)
        _saveprefs.save(objs, self.preffile)
        return

    def log(self, level, log):
        if (self.log_file != None):
            self.log_file.write(level + ": " + log + "\n")
        self.ui.new_log(level + ": " + log)
        return

    def quit(self):
        global shutdown_thread
        shutdown_thread = True;
        gui_cmdwin._HistorySave(self.histfile)

        OpenIPMI.set_log_handler(DummyLogHandler())
        OpenIPMI.shutdown_everything()
        if (self.debug_mem):
            print "OpenIPMI is shutdown, memory problems (SEGVs) after this"
            print " are likely due to OpenIPMI data not being freed until"
            print " after this point due to the python garbage collector"
            pass
        sys.exit()
        return

class DummyLogHandler:
    def __init__(self):
        pass

    def log(self, level, log):
        sys.stderr.write(level + ": " + log + "\n")

class CmdlangEventHandler:
    def __init__(self, app):
        self.app = app
        return
    
    def cmdlang_event(self, event):
        if (not self.app.ui.logevents):
            return
        name = [ "" ]
        value = [ "" ]
        vtype = [ "" ]
        level = [ 0 ]
        event.restart()
        estr = "Event:"
        more = event.next_field(level, vtype, name, value)
        while (more != 0):
            estr += "\n  %*s%s: %s" % (level[0], "", name[0], value[0])
            more = event.next_field(level, vtype, name, value)
            pass
        self.app.ui.new_log(estr)
        return
    
    pass

def trace(frame, event, arg):
    print (event + ": " + frame.f_code.co_name +
           "(" + frame.f_code.co_filename + ":" + str(frame.f_lineno) + ")")
    return trace

def run(args):
    global verbosity

    preffile = os.path.join(os.environ['HOME'], '.openipmigui.startup')
    histfile = os.path.join(os.environ['HOME'], '.openipmigui.history')

    debug_msg = False
    debug_rawmsg = False
    debug_mem = False
    do_trace = False
    read_preffile = True
    log_file = None

    # Skip program name.
    carg = 1

    while (carg < len(args)):
        arg = args[carg]
        carg += 1
        if (arg == "--dmsg"):
            debug_msg = True
        elif (arg == "--drawmsg"):
            debug_msg = True
        elif (arg == "--dmem"):
            debug_mem = True
        elif (arg == "--verbose"):
            verbosity += 1
        elif (arg == "--trace"):
            do_trace = True
        elif (arg == "--logstderr"):
            log_file = sys.stderr
        elif (arg == "--logstdout"):
            log_file = sys.stdout
        elif (arg == "-n"):
            read_preffile = False
        elif (arg == '-p'):
            if (len(args) == 0):
                print "No argument given for -p";
                return
            preffile = args[carg]
            carg += 1
        else:
            print "Unknown argument: " + arg
            return
        pass

    if (debug_mem):
        OpenIPMI.enable_debug_malloc()
        pass

    top = TopHandler(preffile, log_file, histfile)

    # Detect if we need a separate OpenIPMI driver thread.  See the
    # openipmi_driver function above for the reason.
    try:
        import thread
        try:
            top.tk.getvar("tcl_platform", "threaded")
            # Tcl is threaded, no need for another thread.
            need_separate_openipmi_thread = False
        except:
            # Python is threaded, but Tcl is not.  Need to run the
            # OpenIPMI event loop in another thread.
            need_separate_openipmi_thread = True
            pass
        pass
    except:
        # No thread support, can't use another thread.
        need_separate_openipmi_thread = False
        pass

    if (need_separate_openipmi_thread):
        if (verbosity >= 1):
            print "Creating separate OpenIPMI event driver thread"
            pass
        OpenIPMI.init()
        thread.start_new_thread(openipmi_driver, ())
        pass
    else:
        if (verbosity >= 1):
            print "Using TCL event loop, no threads"
            pass
        OpenIPMI.init_tcl()
        pass

    if (debug_rawmsg):
        OpenIPMI.enable_debug_rawmsg()
        pass
    if (debug_msg):
        OpenIPMI.enable_debug_msg()
        pass
    if (do_trace):
        sys.settrace(trace)
        pass

    if (read_preffile):
        _saveprefs.restore(preffile)
    gui_cmdwin._HistoryRestore(histfile)
    
    mainhandler = top

    OpenIPMI.add_domain_change_handler(_domain.DomainWatcher(mainhandler))

    mainhandler.debug_mem = debug_mem
    top.title('OpenIPMI GUI')

    ui = gui.IPMIGUI(top, mainhandler)
    mainhandler.SetUI(ui)

    OpenIPMI.add_domain_change_handler(mainhandler)
    OpenIPMI.set_log_handler(mainhandler)

    _domain.RestoreDomains(mainhandler)

    OpenIPMI.set_cmdlang_event_handler(CmdlangEventHandler(mainhandler))

    top.mainloop()

    mainhandler.quit()


if __name__ == "__main__":
    run(sys.argv)
