# _domain.py
#
# openipmi GUI handling for domains
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

import wx
import OpenIPMI
import _entity
import _mc
import _saveprefs
import _sel
import _conn
import _oi_logging

id_st = 300

class InvalidDomainError(Exception):
    def __init__(self, value):
        self.value = value
    def __repr__(self):
        return repr(self.value)
    def __str__(self):
        return str(self.value)

class DomainOpHandler:
    def __init__(self, d, func, handler):
        self.d = d
        self.func = func
        self.handler = handler
        return

    def DoOp(self):
        self.rv = 0
        rv = self.d.domain_id.to_domain(self)
        if ((rv == 0) and (self.rv != None)):
            rv = self.rv
            pass
        return

    def domain_cb(self, domain):
        if (self.handler):
            self.rv = getattr(domain, self.func)(self.handler)
        else:
            self.rv = getattr(domain, self.func)()
        return


class DomainRefreshData:
    def __init__(self, d, func):
        self.d = d;
        self.item = None
        self.func = func
        return

    def SetItem(self, item):
        self.item = item
        return

    def DoUpdate(self):
        if (not self.item):
            return
        if (not self.d.domain_id):
            return
        self.d.domain_id.to_domain(self)
        return

    def domain_cb(self, domain):
        val = getattr(domain, self.func)()
        self.d.ui.set_item_text(self.item, str(val))
        return

    pass

class DomainSelSet(DomainRefreshData):
    def __init__(self, d):
        self.d = d;
        self.refr = DomainRefreshData(d, "get_sel_rescan_time")
        return

    def DoUpdate(self):
        self.refr.DoUpdate()
        return

    def SetItem(self, item):
        self.refr.SetItem(item)
        return

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(id_st+1, "Modify Value")
        wx.EVT_MENU(self.d.ui, id_st+1, self.modval)
        self.d.ui.PopupMenu(menu, self.d.ui.get_item_pos(eitem))
        menu.Destroy()
        return

    def modval(self, event):
        self.init = True
        self.d.domain_id.to_domain(self)
        dialog = wx.Dialog(None, -1, "Set SEL Rescan Time for " + str(self.d))
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(dialog, -1, "Value:")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        self.field = wx.TextCtrl(dialog, -1, str(self.sel_rescan_time))
        box.Add(self.field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(dialog, -1, "Cancel")
        wx.EVT_BUTTON(dialog, cancel.GetId(), self.cancel)
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(dialog, -1, "Ok")
        wx.EVT_BUTTON(dialog, ok.GetId(), self.ok)
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        dialog.SetSizer(sizer)
        wx.EVT_CLOSE(dialog, self.OnClose)
        dialog.CenterOnScreen();
        dialog.Show(True);
        return

    def cancel(self, event):
        self.dialog.Close()
        return

    def ok(self, event):
        val = self.field.GetValue()
        try:
            self.ival = int(val)
        except:
            return
        self.init = False
        self.d.domain_id.to_domain(self)
        self.dialog.Close()
        return

    def OnClose(self, event):
        self.dialog.Destroy()
        return

    def domain_cb(self, domain):
        if self.init:
            self.sel_rescan_time = domain.get_sel_rescan_time()
        else:
            domain.set_sel_rescan_time(self.ival)
            self.d.sel_rescan_time = self.ival
            self.refr.DoUpdate()
            pass
        return

    pass
        
class DomainIPMBSet(DomainRefreshData):
    def __init__(self, d):
        self.d = d;
        self.refr = DomainRefreshData(d, "get_ipmb_rescan_time")
        return

    def DoUpdate(self):
        self.refr.DoUpdate()
        return

    def SetItem(self, item):
        self.refr.SetItem(item)
        return

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(id_st+10, "Modify Value")
        wx.EVT_MENU(self.d.ui, id_st+10, self.modval)
        self.d.ui.PopupMenu(menu, self.d.ui.get_item_pos(eitem))
        menu.Destroy()
        return

    def modval(self, event):
        self.init = True
        self.d.domain_id.to_domain(self)
        dialog = wx.Dialog(None, -1, "Set IPMB Rescan Time for " + str(self.d))
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(dialog, -1, "Value:")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        self.field = wx.TextCtrl(dialog, -1, str(self.ipmb_rescan_time))
        box.Add(self.field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(dialog, -1, "Cancel")
        wx.EVT_BUTTON(dialog, cancel.GetId(), self.cancel)
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(dialog, -1, "Ok")
        wx.EVT_BUTTON(dialog, ok.GetId(), self.ok)
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        dialog.SetSizer(sizer)
        wx.EVT_CLOSE(dialog, self.OnClose)
        dialog.CenterOnScreen();
        dialog.Show(True);
        return

    def cancel(self, event):
        self.dialog.Close()
        return

    def ok(self, event):
        val = self.field.GetValue()
        try:
            self.ival = int(val)
        except:
            return
        self.init = False
        self.d.domain_id.to_domain(self)
        self.dialog.Close()
        return

    def OnClose(self, event):
        self.dialog.Destroy()
        return

    def domain_cb(self, domain):
        if self.init:
            self.ipmb_rescan_time = domain.get_ipmb_rescan_time()
        else:
            domain.set_ipmb_rescan_time(self.ival)
            self.d.ipmb_rescan_time = self.ival
            self.refr.DoUpdate()
            pass
        return

    pass


class DomainSaver:
    def __init__(self, d, doc, elem):
        self.d = d
        self.doc = doc
        self.elem = elem
        elem.setAttribute("name", self.d.name)
        self.d.domain_id.to_domain(self)
        if (hasattr(self.d, "ipmb_rescan_time")):
            e = doc.createElement("IPMB_rescan_time")
            e.setAttribute("time", str(self.d.ipmb_rescan_time))
            elem.appendChild(e)
            pass
        if (hasattr(self.d, "sel_rescan_time")):
            e = doc.createElement("SEL_rescan_time")
            e.setAttribute("time", str(self.d.sel_rescan_time))
            elem.appendChild(e)
            pass
        return

    def domain_cb(self, domain):
        domain.iterate_connections(self)
        return

    def domain_iter_connection_cb(self, domain, connum):
        args = domain.get_connection_args(connum)
        if (args == None):
            return
        celem = self.doc.createElement("connection")
        celem.setAttribute("contype", args.get_type())
        i = 0
        rv = 0
        while (rv == 0):
            name = [ "" ]
            vtype = [ "" ]
            vrange = [ "" ]
            vhelp = [ "" ]
            value = [ "" ]
            rv = args.get_val(i, name, vtype, vhelp, value, vrange)
            if (rv == 0):
                if (value[0] != None):
                    celem.setAttribute(name[0], value[0])
                    pass
                pass
            i += 1
            pass
        self.elem.appendChild(celem)

class Domain:
    def __init__(self, mainhandler, domain):
        name = domain.get_name()
        if (mainhandler.domains.has_key(name)):
            raise InvalidDomainError("Domain name already exists")
        self.name = name
        self.mainhandler = mainhandler
        self.ui = mainhandler.ui
        self.entities = { }
        self.mcs = { }
        self.connections = { }
        self.domain_id = domain.get_id()
        
        mainhandler.domains[name] = self
        
        self.ui.add_domain(self)

        self.refreshers = [ ]
        self.add_refr_item("SEL Count", DomainRefreshData(self, "sel_count"))
        self.add_refr_item("SEL Entries Used",
                           DomainRefreshData(self, "sel_entries_used"))
        self.add_refr_item("IPMB Rescan Time", DomainIPMBSet(self))
        self.add_refr_item("SEL Rescan Time", DomainSelSet(self))
        self.add_refr_item("GUID", DomainRefreshData(self, "get_guid"))
        self.add_refr_item("Type", DomainRefreshData(self, "get_type"))
        
        self.first_conn = False
        self.any_con_up = False
        self.ui.incr_item_critical(self.treeroot)

        domain.add_connect_change_handler(self)
        return

    def __str__(self):
        return self.name

    def add_refr_item(self, name, refr):
        item = self.ui.prepend_item(self, name, None, refr)
        refr.SetItem(item)
        self.refreshers.append(refr)
        return refr
        
    def getTag(self):
        return "domain"

    def SaveInfo(self, doc, elem):
        DomainSaver(self, doc, elem)
        return

    def HandleExpand(self, event):
        for i in self.refreshers:
            i.DoUpdate()
            pass
        return

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(id_st+20, "Close")
        wx.EVT_MENU(self.ui, id_st+20, self.CloseMenuHandler)
        item = menu.Append(id_st+21, "Reread SELs")
        wx.EVT_MENU(self.ui, id_st+21, self.RereadSelsHandler)
        item = menu.Append(id_st+22, "Display SELs")
        wx.EVT_MENU(self.ui, id_st+22, self.DisplaySelsHandler)
        item = menu.Append(id_st+23, "Rescan IPMB")
        wx.EVT_MENU(self.ui, id_st+23, self.RescanIPMBHandler)
        self.ui.PopupMenu(menu, self.ui.get_item_pos(eitem))
        menu.Destroy()
        return

    def CloseMenuHandler(self, event):
        self.domain_id.to_domain(self)
        return

    def RereadSelsHandler(self, event):
        dop = DomainOpHandler(self, "reread_sels", None)
        dop.DoOp()
        return

    def DisplaySelsHandler(self, event):
        _sel.DomainSELDisplay(self.domain_id)
        return

    def RescanIPMBHandler(self, event):
        dop = DomainOpHandler(self, "start_full_ipmb_scan", None)
        dop.DoOp()
        return

    def Connect(self):
        self.already_up = False
        self.domain_id = OpenIPMI.open_domain3(self.name, [], self.connection,
                                               self, self)
        del self.connection
        if (self.domain_id == None):
            raise InvalidDomainError("Open domain failed, invalid parms")
        return

    def conn_change_cb(self, domain, err, connum, portnum, connected):
        if (not self.first_conn):
            self.first_conn = True
            if (hasattr(self, "ipmb_rescan_time")):
                domain.set_ipmb_rescan_time(self.ipmb_rescan_time)
                pass
            if (hasattr(self, "sel_rescan_time")):
                domain.set_sel_rescan_time(self.sel_rescan_time)
                pass
            domain.iterate_connections(self)
            pass
        self.connections[connum].SetPortUp(portnum, connected)
        any_con_up = False
        for c in self.connections.itervalues():
            any_con_up = c.IsUp() or any_con_up
            pass
        if (any_con_up):
            if (not self.any_con_up):
                self.ui.decr_item_critical(self.treeroot)
                pass
            pass
        else:
            if (self.any_con_up):
                self.ui.incr_item_critical(self.treeroot)
                pass
            pass
        self.any_con_up = any_con_up
        return

    def domain_iter_connection_cb(self, domain, conn):
        _conn.Connection(domain, self, conn)
        return
    
    def connected(self, domain):
        domain.add_entity_update_handler(self)
        domain.add_mc_update_handler(self)
        return

    def find_or_create_entity(self, entity):
        ename = entity.get_name()
        if (ename in self.entities):
            return self.entities[ename];
        else:
            return _entity.Entity(self, entity)
        return
        
    def entity_update_cb(self, op, domain, entity):
        if (op == "added"):
            e = self.find_or_create_entity(entity)
            entity.add_sensor_update_handler(e)
            entity.add_control_update_handler(e)
        elif (op == "removed"):
            self.entities[entity.get_name()].remove()
        else:
            e = self.find_or_create_entity(entity)
            e.Changed(entity)
            pass
        return
        
    def find_or_create_mc(self, mc):
        mname = mc.get_name()
        if (mname in self.mcs):
            return self.mcs[mname];
        else:
            return _mc.MC(self, mc)
        return
        
    def mc_update_cb(self, op, domain, mc):
        if (op == "added"):
            _mc.MC(self, mc)
            pass
        elif (op == "removed"):
            self.entities[mc.get_name()].remove()
        else:
            m = self.find_or_create_mc(mc)
            m.Changed(mc)
            pass
        return
        
    def domain_cb(self, domain):
        domain.close(self)
        return

    def domain_close_done_cb(self):
        return
        
    def remove(self):
        if (self.domain_id != None):
            self.domain_id.to_domain(self)
            pass
        self.mainhandler.domains.pop(self.name);
        self.ui.remove_domain(self)
        return

defaultDomains = [ ]

# Catch new and removed domains here
class DomainWatcher:
    def __init__(self, mainhandler):
        self.mainhandler = mainhandler
        return

    def domain_change_cb(self, change, domain):
        if (change == "added"):
            Domain(self.mainhandler, domain)
            pass
        elif (change == "deleted"):
            name = domain.get_name();
            if (name in self.mainhandler.domains):
                self.mainhandler.domains[name].remove()
                pass
            pass
        return

class OtherDomainInfo:
    pass

class DomainInfoSetup:
    def __init__(self, other, domain_id):
        self.other = other
        domain_id.to_domain(self)
        return

    def domain_cb(self, domain):
        if (hasattr(self.other, "ipmb_rescan_time")):
            domain.set_ipmb_rescan_time(self.other.ipmb_rescan_time)
            pass
        if (hasattr(self.other, "sel_rescan_time")):
            domain.set_sel_rescan_time(self.other.sel_rescan_time)
            pass
        return

def RestoreDomains(mainhandler):
    for i in defaultDomains:
        name = i[0]
        attrhashes = i[1]
        other = i[2]
        connects = [ ]
        for attrhash in attrhashes:
            if ("contype" not in attrhash):
                continue
            args = OpenIPMI.alloc_empty_args(str(attrhash["contype"]))
            if (args == None):
                continue
            for attr in attrhash.items():
                vname = str(attr[0])
                if (vname == "contype"):
                    continue
                value = str(attr[1])
                args.set_val(0, vname, value)
                pass
            connects.append(args)
            pass
        domain_id = OpenIPMI.open_domain3(name, [], connects, None, None)
        if (domain_id != None):
            DomainInfoSetup(other, domain_id)
            pass
        else:
            _oi_logging.error("Error making domain connection for " + name)
            pass
        pass
    return


class _DomainRestore(_saveprefs.RestoreHandler):
    def __init__(self):
        _saveprefs.RestoreHandler.__init__(self, "domain")
        return

    def restore(self, node):
        name = str(node.getAttribute("name"));
        if (name == ""):
            return
        connects = [ ]
        other = OtherDomainInfo()
        for c in node.childNodes:
            if (c.nodeType == c.ELEMENT_NODE):
                if (c.nodeName == "connection"):
                    attrhash = { }
                    for i in range(0, c.attributes.length):
                        attr = c.attributes.item(i)
                        attrhash[attr.nodeName] = attr.nodeValue
                        pass
                    connects.append(attrhash)
                    pass
                elif (c.nodeName == "IPMB_rescan_time"):
                    try:
                        other.ipmb_rescan_time = int(c.getAttribute("time"))
                    except:
                        _oi_logging.error("Error restoring IPMB rescan time"
                                          + " in a domain")
                        pass
                    pass
                elif (c.nodeName == "SEL_rescan_time"):
                    try:
                        other.sel_rescan_time = int(c.getAttribute("time"))
                    except:
                        _oi_logging.error("Error restoring SEL rescan time"
                                          + " in a domain")
                        pass
                    pass
                pass
            pass
        defaultDomains.append([name, connects, other])
        return
    pass

_DomainRestore()
