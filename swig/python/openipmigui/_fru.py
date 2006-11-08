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

class ReinitOnAny:
    def __init__(self, glist):
        self.glist = glist;
        return

    def reinit(self, data, s_oldval, s_newval):
        oldval = int(s_oldval)
        newval = int(s_newval)
        if (oldval != newval):
            self.glist.refresh()
            return True
        return False

    pass

class ReinitOnZero:
    def __init__(self, glist):
        self.glist = glist;
        return

    def reinit(self, data, s_oldval, s_newval):
        oldval = int(s_oldval)
        newval = int(s_newval)
        if (oldval != newval) and ((oldval == 0) or (newval == 0)):
            self.glist.refresh()
            return True
        return False

    pass

class FRUData:
    def __init__(self, glist, node, index, pname, ptype, origval, parent,
                 settable, reiniter = None):
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
        self.reiniter = reiniter
        self.settable = settable
        if (ptype == "binary") or (ptype == "unicode"):
            self.longtext = True
            pass
        else:
            self.longtext = False;
            pass

        enums = None
        cpos = [ -1 ]
        npos = [ 0 ]
        val = [ "" ]
        rv = self.node.get_enum_val(self.aidx, cpos, npos, val)
        if (rv == 0):
            enums = [ ]
            while (rv == 0):
                enums.append(val[0])
                if (npos[0] == -1):
                    break
                cpos[0] = npos[0]
                val = [ "" ]
                rv = self.node.get_enum_val(self.aidx, cpos, npos, val)
                pass
            pass
        self.enums = enums
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
                if (self.enums != None):
                    for v in self.enums:
                        menul.append( (v, self.setenum, v) )
                        pass
                    pass
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

    def setenum(self, val):
        self.ok([ val ])
        return
    
    def ok(self, vals):
        rv = self.node.set_field(self.aidx, self.ptype, str(vals[0]))
        if (rv != 0):
            self.glist.SetError("Invalid data value: "
                                + OpenIPMI.get_error_string(rv))
            return
        try:
            if (self.reiniter != None):
                if self.reiniter.reinit(self, self.currval, vals[0]):
                    return
                pass
            pass
        except:
            pass
        
        name_s = [ "" ]
        type_s = [ "" ]
        value_s = [ "" ]
        node_s = [ None ]
        rv = self.node.get_field(self.aidx, name_s, type_s, value_s, node_s)
        if (rv != 0):
            self.glist.SetError("Could not re-get field: "
                                + OpenIPMI.get_error_string(rv))
            return

        self.glist.cleanup_field(type_s[0], value_s)
        self.currval = value_s[0]
        self.glist.SetColumn(self.item, self.currval, 1)
        return
    
    def delete_item(self, event):
        self.parent.delete_element(self)
        return
    
    def ins_before(self, event):
        self.parent.insert_element(self)
        return
    
    def setvalue(self, event):
        gui_setdialog.SetDialog("Set value for " + self.pname,
                                [ self.currval ], 1, self,
                                longtext=self.longtext)
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

class ArrayFRUData(FRUData):
    def __init__(self, glist, node, index, subnode, pname, ptype, length,
                 parent, settable):
        FRUData.__init__(self, glist, node, index, pname, ptype, length,
                         parent, settable, False)
        self.subnode = subnode
        self.children = [ ]
        self.length = length
        return

    def do_on_close(self):
        self.children = [ ]
        FRUData.do_on_close(self)
        return
        
    def HandleMenu(self, event, idx, point):
        menul = [ ]
        if (self.settable):
            menul.append( ("Add an array element", self.add_element) )
            pass
        if (self.parent != None):
            menul.append( ("Delete", self.delete_item) )
            menul.append( ("Insert Before", self.ins_before) )
            pass
        if (len(menul) > 0):
            gui_popup.popup(self.glist, event, menul, point)
        return

    def reidx_children(self):
        i = 0
        for l in self.children:
            l.aidx = i
            self.glist.SetColumn(l.item, str(i), 0)
            i += 1
            pass
        return

    def redisplay_item(self, idx, before=None):
        name_s = [ "" ]
        type_s = [ "" ]
        value_s = [ "" ]
        node_s = [ None ]
        rv = self.subnode.get_field(idx, name_s, type_s, value_s, node_s)
        if (rv != 0):
            self.glist.SetError("Could not get field: "
                                + OpenIPMI.get_error_string(rv))
            return
        self.glist.add_fru_data(self.item, self.subnode, idx,
                                self, False, idx, before)
        return
    
    def add_element(self, event):
        self.node.set_field(self.aidx, "integer", str(self.length))
        self.redisplay_item(self.length)
        self.length += 1
        return

    def delete_element(self, child):
        rv = self.node.set_field(self.aidx, "integer", str(-(child.aidx+1)))
        if (rv != 0):
            self.glist.SetError("Could not delete item: "
                                + OpenIPMI.get_error_string(rv))
            return
        self.glist.Remove(child.item)
        del self.children[child.aidx]
        self.reidx_children()
        self.length -= 1
        return
        
    def insert_element(self, child):
        rv = self.node.set_field(self.aidx, "integer", str(child.aidx))
        if (rv != 0):
            self.glist.SetError("Could not insert item: "
                                + OpenIPMI.get_error_string(rv))
            return
        self.redisplay_item(child.aidx, child.item)
        self.reidx_children()
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

    def cleanup_field(self, type, value_s):
        if (type == "binary"):
            splitup = value_s[0].split()
            p = 0
            value_s[0] = ""
            if (len(splitup) > 0):
                value_s[0] += splitup[0]
                del splitup[0]
                pass
            for v in splitup:
                p += 1
                if (p >= 8):
                    value_s[0] += "\n"
                    p = 0
                    pass
                else:
                    value_s[0] += " "
                    pass
                value_s[0] += v
                pass
            pass
        return
    
    def refresh(self):
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
                        data = ArrayFRUData(self, node, i, node_s[0],
                                            name_s[0], node_s[0].get_subtype(),
                                            int(value_s[0]), parent, True)
                        np = data
                        pass
                    else:
                        data = FRUData(self, node, i, name_s[0], type_s[0],
                                       None, parent, node.settable(i) == 0,
                                       False)
                        pass
                    sub = self.add_data(item, name_s[0], [], data,
                                        before=before)
                    self.add_fru_data(sub, node_s[0], 0, np, False)
                else:
                    reiniter = None
                    if (normal_top):
                        if (name_s[0] == "multi_record_offset"):
                            reiniter = ReinitOnAny(self)
                            pass
                        elif name_s[0].endswith("_offset"):
                            reiniter = ReinitOnZero(self)
                            pass
                        pass
                    self.cleanup_field(type_s[0], value_s)
                    data = FRUData(self, node, i, name_s[0], type_s[0],
                                   value_s[0], parent, node.settable(i) == 0,
                                   reiniter)
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
