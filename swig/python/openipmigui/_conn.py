# _conn.py
#
# openipmi GUI handling for connections
#
# Author: MontaVista Software, Inc.
#         Corey Minyard <minyard@mvista.com>
#         source@mvista.com
#
# Copyright 2006 MontaVista Software Inc.
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
import gui_popup
import gui_SoL

class Port:
    def __init__(self, domain, c, pnum):
        self.c = c
        self.pnum = pnum
        self.ui = c.ui
        self.name = c.d.name + "(" + str(c.cnum) + "." + str(pnum) + ")"

        c.ports[pnum] = self

        self.ui.add_port(c, self)

        # Wait to get activation information
        self.up = False
        self.ui.incr_item_warning(self.treeroot)

        pi = domain.get_port_info(c.cnum, pnum);
        if (pi != None):
            self.ui.set_item_text(self.treeroot, pi)
            pass

        v = [ 0 ]
        rv = domain.is_connection_port_up(c.cnum, pnum, v)
        if (rv == 0):
            self.SetUp(domain, v[0])
        return

    def remove(self):
        self.c = None
        self.ui = None
        return

    def __str__(self):
        return self.name

    def SetUp(self, domain, up):
        pi = domain.get_port_info(self.c.cnum, self.pnum);
        if (pi != None):
            self.ui.set_item_text(self.treeroot, pi)
            pass

        if (up):
            if (not self.up):
                self.ui.decr_item_warning(self.treeroot)
                pass
            pass
        else:
            if (self.up):
                self.ui.incr_item_warning(self.treeroot)
                pass
            pass
        self.up = up
        return

    def IsUp(self):
        return self.up

    pass

class Connection:
    def __init__(self, domain, d, cnum):
        self.d = d
        self.cnum = cnum
        self.ui = d.ui
        self.name = d.name + "(" + str(cnum) + ")"
        self.ports = { }
        self.domain_id = domain.get_id()

        d.connections[cnum] = self

        v = [ 0 ]
        rv = domain.is_connection_active(cnum, v)
        if (rv == 0):
            if (v[0] != 0):
                self.active_str = "active"
                pass
            else:
                self.active_str = "inactive"
                pass
            pass
        else:
            self.active_str = "inactive(" + str(rv) + ")"
            pass

        self.ui.add_connection(d, self)
        self.ui.set_item_text(self.treeroot,
                              (domain.get_connection_type(cnum)
                               + " (" + self.active_str + ")"))

        v = [ 0 ]
        rv = domain.num_connection_ports(cnum, v)
        if (rv == 0):
            num_ports = v[0]
            for i in range(0, num_ports):
                Port(domain, self, i)
                pass
            pass
        self.conup = False
        self.ui.incr_item_severe(self.treeroot)
        return

    def remove(self):
        self.ui = None
        for p in self.ports.itervalues():
            p.remove()
            pass
        self.ports = None
        return
    
    def __str__(self):
        return self.name

    def DoUpdate(self):
        self.op = "checkactive"
        self.domain_id.to_domain(self)
        return
    
    def SetPortUp(self, domain, port, err):
        if (port not in self.ports):
            Port(domain, self, port)
            pass
        if (err == OpenIPMI.enoent):
            self.ui.remove_port(self.ports[port])
            del self.ports[port];
            return
        
        self.ports[port].SetUp(domain, err == 0)
        conup = False
        for p in self.ports.itervalues():
            conup = p.IsUp() or conup
            pass
        if (conup):
            if (not self.conup):
                self.ui.decr_item_severe(self.treeroot)
                pass
            pass
        else:
            if (self.conup):
                self.ui.incr_item_severe(self.treeroot)
                pass
            pass
        self.conup = conup
        return

    def IsPortUp(self, port):
        return self.ports[port].IsUp(port)

    def IsUp(self):
        return self.conup
    
    def HandleMenu(self, event):
        gui_popup.popup(self.ui, event,
                        [ [ "Activate", self.Activate ],
                          [ "Open SOL", self.OpenSOL ] ])
        return

    def Activate(self, event):
        self.op = "activate"
        self.domain_id.to_domain(self)
        return

    def OpenSOL(self, event):
        gui_SoL.SoL(self.ui, self.domain_id, self.cnum)
        return
    
    def domain_cb(self, domain):
        if (self.op == "activate"):
            domain.activate_connection(self.cnum)
        elif (self.op == "checkactive"):
            v = [ 0 ]
            rv = domain.is_connection_active(self.cnum, v)
            if (rv == 0):
                if (v[0] != 0):
                    new_active_str = "active"
                    pass
                else:
                    new_active_str = "inactive"
                    pass
                pass
            else:
                new_active_str = "inactive("+ str(rv) + ")"
                pass

            if (new_active_str != self.active_str):
                self.active_str = new_active_str
                self.ui.set_item_text(self.treeroot,
                                      (domain.get_connection_type(self.cnum)
                                       + " (" + self.active_str + ")"))
                pass
            pass
        return

    pass
