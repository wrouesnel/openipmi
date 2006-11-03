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
import gui_popup
import gui_setdialog

class FRUData:
    def __init__(self, glist, node, index, pname, ptype, origval, parent,
                 reinit_on_zero, settable):
        self.glist = glist
        self.node = node
        self.aidx = index
        self.pname = pname
        self.ptype = ptype
        self.origval = origval
        self.currval = origval
        self.parent = parent
        if (parent != None):
            parent.children.insert(index, self)
            pass
        self.reinit_on_zero = reinit_on_zero
        self.settable = settable
        return

    def do_on_close(self):
        self.parent = None
        return
        
    def SetItem(self, item):
        self.item = item
        return

    def HandleMenu(self, event, idx, point):
        menul = [ ]
        if (self.settable):
            if (self.ptype == "boolean"):
                menul.append( ("Toggle Value", self.togglevalue) )
                pass
            else:
                menul.append( ("Set Value", self.setvalue) )
                pass
            pass
        if (self.parent != None):
            menul.append( ("Delete", self.delete_item) )
            menul.append( ("Insert Before", self.ins_before) )
            pass
        if (len(menul) > 0):
            gui_popup.popup(self.glist, event, menul, point)
            pass
        return

    def ok(self, vals):
        rv = self.node.set_field(self.aidx, self.ptype, str(vals[0]))
        if (rv != 0):
            self.glist.SetError("Invalid data value: "
                                + OpenIPMI.get_error_string(rv))
            return
        try:
            oldval = int(self.currval)
            newval = int(vals[0])
            if (self.reinit_on_zero and (oldval != newval)
                and ((oldval == 0) or (newval == 0))):
                # We need to re-initialize the whole display.
                self.glist.refresh_data()
                return
            pass
        except:
            pass
        self.currval = vals[0]
        self.glist.SetColumn(self.item, self.currval, 1)
        return
    
    def delete_item(self, event):
        rv = self.parent.node.set_field(self.aidx, self.ptype, None)
        if (rv != 0):
            self.glist.SetError("Could not delete item: "
                                + OpenIPMI.get_error_string(rv))
            return
        self.glist.Remove(self.item)
        del self.parent.children[self.aidx]
        i = 0
        for l in self.parent.children:
            l.aidx = i
            self.glist.SetColumn(l.item, str(i), 0)
            i += 1
            pass
        self.parent.length -= 1
        return
    
    def ins_before(self, event):
        if ((self.ptype == "binary") or (self.ptype == "unicode")
            or (self.ptype == "ascii")):
            value = " "
            pass
        elif (self.ptype == "subnode"):
            value = ""
            pass
        elif (self.ptype == "boolean"):
            value = "false"
            pass
        else:
            value = "0"
            pass
        rv = self.parent.node.set_field(self.aidx, self.ptype, value)
        if (rv != 0):
            self.glist.SetError("Could not insert item: "
                                + OpenIPMI.get_error_string(rv))
            return
        name_s = [ "" ]
        type_s = [ "" ]
        value_s = [ "" ]
        node_s = [ None ]
        rv = self.parent.node.get_field(self.aidx, name_s, type_s, value_s,
                                        node_s)
        if (rv != 0):
            self.glist.SetError("Could not get field: "
                                + OpenIPMI.get_error_string(rv))
            return
        if (type_s[0] == "boolean"):
            value_s[0] = str(bool(int(value_s[0])))
        self.glist.add_fru_data(self.parent.myitem, self.parent.node,
                                self.aidx, self.parent, False, self.aidx,
                                self.item)
        i = 0
        for l in self.parent.children:
            l.aidx = i
            self.glist.SetColumn(l.item, str(i), 0)
            i += 1
            pass
        self.parent.length += 1
        return
    
    def setvalue(self, event):
        gui_setdialog.SetDialog("Set value for " + self.pname,
                                [ self.currval ], 1, self)
        return

    def togglevalue(self, event):
        if (self.currval == "True"):
            newval = "False"
        else:
            newval = "True"
            pass
        rv = self.node.set_field(self.aidx, self.ptype, newval)
        if (rv != 0):
            self.glist.SetError("Could not toggle value: "
                                + OpenIPMI.get_error_string(rv))
            return
        self.currval = newval
        self.glist.SetColumn(self.item, newval, 1)
        return

    pass

class FRUArrayData:
    def __init__(self, glist, node, index, pname, ptype, length, parent,
                 settable):
        self.glist = glist
        self.node = node
        self.aidx = index
        self.pname = pname
        self.ptype = ptype
        self.length = length
        self.parent = parent
        self.children = [ ]
        if (parent != None):
            parent.children.insert(index, self)
            pass
        self.settable = settable
        return

    def do_on_close(self):
        self.children = [ ]
        self.parent = None
        return
        
    def SetItem(self, item):
        self.item = item
        return

    def HandleMenu(self, event, idx, point):
        menul = [ ]
        if (self.settable):
            menul.append( ("Add an array element", self.add_element) )
            pass
        if (self.parent != None):
            menul.append( ("Delete", self.delete_item) )
            pass
        if (len(menul) > 0):
            gui_popup.popup(self.glist, event, menul, point)
        return

    def delete_item(self, event):
        rv = self.parent.node.set_field(self.aidx, self.ptype, None)
        if (rv != 0):
            self.glist.SetError("Could not delete item: "
                                + OpenIPMI.get_error_string(rv))
            return
        self.glist.Remove(self.item)
        del self.parent.children[self.aidx]
        i = 0
        for l in self.parent.children:
            l.aidx = i
            self.glist.SetColumn(l.item, str(i), 0)
            i += 1
            pass
        self.parent.length -= 1
        return
    
    def add_element(self, event):
        if ((self.ptype == "binary") or (self.ptype == "unicode")
            or (self.ptype == "ascii")):
            value = " "
            pass
        elif (self.ptype == "subnode"):
            value = ""
            pass
        elif (self.ptype == "boolean"):
            value = "false"
            pass
        else:
            value = "0"
            pass
        rv = self.node.set_field(self.length, self.ptype, value)
        if (rv != 0):
            self.glist.SetError("Could not set field: "
                                + OpenIPMI.get_error_string(rv))
            return
        name_s = [ "" ]
        type_s = [ "" ]
        value_s = [ "" ]
        node_s = [ None ]
        rv = self.node.get_field(self.length, name_s, type_s, value_s, node_s)
        if (rv != 0):
            self.glist.SetError("Could not get field: "
                                + OpenIPMI.get_error_string(rv))
            return
        self.glist.add_fru_data(self.myitem, self.node, self.length,
                                self, False)
        
        self.length += 1
        return

    pass

class FruInfoDisplay(gui_treelist.TreeList):
    def __init__(self, fru, name):
        self.fru = fru
        name_s = [ "" ]
        node_s = [ None ]
        rv = fru.get_root_node(name_s, node_s)
        if (rv != 0):
            _oi_logging.error("unable to get FRU node: " + str(rv))
            return

        self.fru_type = name_s[0]
        
        gui_treelist.TreeList.__init__(self, "FRU info for " + name,
                                       ".",
                                       [("Name", 300), ("Value", 300)])

        self.add_fru_data(self.treeroot, node_s[0], 0, None,
                          self.fru_type == "standard FRU")
        self.AfterDone()
        self.ExpandItem("")
        return

    def do_on_close(self):
        self.fru = None
        return
        
    def cancel(self):
        self.Close()
        return

    def fru_written(self, domain, fru, err):
        if (err):
            self.glist.SetError("Could not write FRU: "
                                + OpenIPMI.get_error_string(err))
            return
        self.Close()
        return
    
    def save(self):
        self.fru.write(self)
        self.Close()
        return

    def refresh_data(self):
        name_s = [ "" ]
        node_s = [ None ]
        rv = self.fru.get_root_node(name_s, node_s)
        if (rv != 0):
            _oi_logging.error("unable to get FRU node: " + str(rv))
            return

        self.fru_type = name_s[0]
        self.RemoveAll()
        self.add_fru_data(self.treeroot, node_s[0], 0, None,
                          self.fru_type == "standard FRU")
        self.AfterDone()
        self.ExpandItem("")
        return
    
    def add_fru_data(self, item, node, startidx, parent, normal_top,
                     endidx=-1, before=None):
        i = startidx
        while True:
            name_s = [ "" ]
            type_s = [ "" ]
            value_s = [ "" ]
            node_s = [ None ]
            rv = node.get_field(i, name_s, type_s, value_s, node_s)
            if (rv == OpenIPMI.einval):
                return
            if (type_s[0] == "boolean"):
                value_s[0] = str(bool(int(value_s[0])))
            # Ignore other errors, just keep going
            if (rv == 0):
                if (name_s[0] == None):
                    name_s[0] = str(i)
                    pass
                if (type_s[0] == "subnode"):
                    np = None
                    if (node.settable(i) == 0) and (value_s[0] != "-1"):
                        # A settable array
                        data = FRUArrayData(self, node_s[0], i, name_s[0],
                                            node_s[0].get_subtype(),
                                            int(value_s[0]), parent, True)
                        np = data
                        pass
                    else:
                        data = FRUData(self, node, i, name_s[0], type_s[0],
                                       None, parent, False,
                                       node.settable(i) == 0)
                        pass
                    sub = self.add_data(item, name_s[0], [], data,
                                        before=before)
                    if (data != None):
                        data.myitem = sub
                        pass
                    self.add_fru_data(sub, node_s[0], 0, np, False)
                else:
                    data = FRUData(self, node, i, name_s[0], type_s[0],
                                   value_s[0], parent,
                                   (normal_top and
                                    name_s[0].endswith("_offset")),
                                   node.settable(i) == 0)
                    self.add_data(item, name_s[0], [value_s[0]], data=data,
                                  before=before)
                    pass
                pass
            if (endidx >= 0) and (i == endidx):
                break
            i = i + 1
            pass
        return
    
    pass
