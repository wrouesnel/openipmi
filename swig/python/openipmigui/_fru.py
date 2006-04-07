# _fru.py
#
# openipmi GUI handling for FRU data
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

import OpenIPMI
import _oi_logging
import gui_treelist

class FruInfoDisplay(gui_treelist.TreeList):
    def __init__(self, fru, name):
        self.fru = fru;
        name_s = [ "" ]
        node_s = [ None ]
        rv = fru.get_root_node(name_s, node_s)
        if (rv != 0):
            _oi_logging.error("unable to get FRU node: " + str(rv))
            return

        gui_treelist.TreeList.__init__(self, "FRU info for " + name,
                                       name_s[0],
                                       [("Name", 300), ("Value", 100)]);

        self.add_fru_data(self.treeroot, node_s[0])
        self.AfterDone()
        return

    def ok(self, event):
        self.Close()
        return

    def add_fru_data(self, item, node):
        i = 0
        while True:
            name_s = [ "" ]
            type_s = [ "" ]
            value_s = [ "" ]
            node_s = [ None ]
            rv = node.get_field(i, name_s, type_s, value_s, node_s)
            if (rv == OpenIPMI.einval):
                return
            if (rv == 0):
                if (name_s[0] == None):
                    name_s[0] = str(i)
                    pass
                # Ignore other errors, just keep going
                if (type_s[0] == "subnode"):
                    sub = self.Append(item, name_s[0], [])
                    self.add_fru_data(sub, node_s[0])
                else:
                    self.Append(item, name_s[0], [value_s[0]])
                    pass
                pass
            i = i + 1
            pass
        return
