# _mc_pefparm.py
#
# openipmi GUI handling for MC PEF parms
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

import sys
import OpenIPMI
import _oi_logging
import gui_errstr
import gui_list
import gui_popup
import gui_setdialog

class MCPEFData:
    def __init__(self, glist, pefc, parm, aidx, pname, ptype, origval):
        self.glist = glist
        self.pefc = pefc
        self.parm = parm
        self.aidx = aidx
        self.pname = pname
        self.ptype = ptype
        self.origval = origval
        self.currval = origval
        return

    def SetItem(self, idx):
        self.idx = idx;
        return

    def HandleMenu(self, event, idx, point):
        if (self.ptype == "bool"):
            menul = [ ("Toggle Value", self.togglevalue) ]
        elif (self.ptype == "enum"):
            menul = [ ]
            nval = [ 0 ]
            sval = [ "" ]
            val = 0;
            while (val != -1):
                rv = OpenIPMI.pefconfig_enum_val(self.parm, val, nval, sval)
                if (rv == 0):
                    menul.append( (sval[0] + " (" + str(val) + ")",
                                   self.setenum,
                                   val) )
                    pass
                val = nval[0];
                pass
            pass
        else:
            menul = [ ("Set Value", self.setvalue) ]
            pass
        gui_popup.popup(self.glist, event, menul, point)
        return

    def ok(self, vals):
        rv = self.pefc.set_val(self.parm, self.aidx, self.ptype, str(vals[0]))
        if (rv != 0):
            self.glist.SetError("Invalid data value: "
                                + OpenIPMI.get_error_string(rv))
            return
        self.currval = vals[0]
        self.glist.SetColumn(self.idx, 1, vals[0])
        return
    
    def setvalue(self, event):
        gui_setdialog.SetDialog("Set value for " + self.pname,
                                [ self.currval ], 1, self)
        return

    def setenum(self, val):
        rv = self.pefc.set_val(self.parm, self.aidx, "integer", str(val))
        if (rv != 0):
            self.glist.SetError("Could not set value to " + str(val) + ": "
                                + OpenIPMI.get_error_string(rv))
            return
        self.currval = val
        nval = [ 0 ]
        sval = [ "" ]
        OpenIPMI.pefconfig_enum_val(self.parm, val, nval, sval)
        self.glib.SetColumn(self.idx, 1, sval[0])
        return
    
    def togglevalue(self, event):
        if (self.currval == "true"):
            newval = "false"
        else:
            newval = "true"
            pass
        rv = self.pefc.set_val(self.parm, self.aidx, self.ptype, newval)
        if (rv != 0):
            self.glist.SetError("Could not toggle value: "
                                + OpenIPMI.get_error_string(rv))
            return
            
        self.currval = newval
        self.glist.SetColumn(self.idx, 1, newval)
        return

    pass

class MCPefParm(gui_list.List):
    def __init__(self, m, pef, pefc):
        gui_list.List.__init__(self,
                               "PEFPARMS for " + m.name,
                               [ ("Name", 250), ("Value", 250) ])
        self.pef = pef
        self.pefc = pefc
        
        i = 0
        j = 0
        rv = True
        v = [ 0 ]
        while (rv):
            lastv = v[0]
            rv = pefc.get_val(i, v)
            if (rv):
                vals = rv.split(" ", 2)
                if (len(vals) == 3):
                    # Valid parm
                    if (vals[1] == "integer"):
                        w = [ 0 ]
                        x = [ "" ]
                        err = OpenIPMI.pefconfig_enum_val(i, 0, w, x)
                        if (err != OpenIPMI.enosys):
                            vals[1] = "enum"
                            pass
                        pass

                    data = MCPEFData(self, pefc, i, lastv,
                                     vals[0], vals[1], vals[2])

                    if (v[0] == 0):
                        title = vals[0]
                    else:
                        x = [ "" ]
                        err = OpenIPMI.pefconfig_enum_idx(i, lastv, x)
                        if (err):
                            title = vals[0] + "[" + str(lastv) + "]"
                        else:
                            title = vals[0] + "[" + x[0] + "]"
                            pass
                        pass
                    if (vals[1] == "enum"):
                        nval = [ 0 ]
                        sval = [ "" ]
                        OpenIPMI.pefconfig_enum_val(data.parm, int(vals[2]),
                                                    nval, sval)
                        value = sval[0]
                        pass
                    else:
                        value = vals[2]
                        pass

                    self.add_data(title, [ value ], data)
                    
                    j += 1
                    if (v[0] == 0):
                        i += 1
                        pass
                    if (v[0] == -1):
                        i += 1
                        v[0] = 0
                        pass
                    pass
                else:
                    v[0] = 0
                    i += 1
                    pass
                pass
            pass

        self.AfterDone()
        return

    def save(self):
        rv = self.pef.set_config(self.pefc)
        if (rv != 0):
            self.errstr.SetError("Error setting config: "
                                 + OpenIPMI.get_error_string(rv))
            return

        # Don't forget to set self.pef to None when done so OnClose
        # doesn't clear it again
        self.pef = None
        self.Close()
        return

    def cancel(self):
        self.Close()
        return

    def do_on_close(self):
        # Do it here, not in cancel, to handle closing the window without
        # clicking on "save" or "cancel"
        if (self.pef):
            self.pef.clear_lock(self.pefc)
            self.pef = None
            pass
        self.pefc = None
        return
    
    pass
