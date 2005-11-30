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

class InvalidDomainInfo(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class DomainRefreshData:
    def __init__(self, d):
        self.d = d;

    def domain_cb(self, domain):
        self.d.ipmb_rescan_time = domain.get_ipmb_rescan_time()
        self.d.sel_rescan_time = domain.get_sel_rescan_time()
        self.d.ui.set_item_text(self.d.irscn,
                                "IPMB Rescan Time",
                                str(self.d.ipmb_rescan_time))
        self.d.ui.set_item_text(self.d.srscn, "SEL Rescan Time",
                                str(self.d.sel_rescan_time))
        self.d.ui.set_item_text(self.d.dguid, "GUID",
                                domain.get_guid())
        self.d.ui.set_item_text(self.d.dtype, "Type",
                                domain.get_type())


class DomainSelSet:
    def __init__(self, d):
        self.d = d;

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(-1, "Modify Value")
        self.d.ui.Bind(wx.EVT_MENU, self.modval, item)
        self.d.ui.PopupMenu(menu, self.d.ui.get_item_pos(eitem))
        menu.Destroy()

    def modval(self, event):
        dialog = wx.Dialog(None, -1, "Set SEL Rescan Time")
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(dialog, -1, "Value:")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        self.field = wx.TextCtrl(dialog, -1, str(self.d.sel_rescan_time))
        box.Add(self.field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(dialog, -1, "Cancel")
        dialog.Bind(wx.EVT_BUTTON, self.cancel, cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(dialog, -1, "Ok")
        dialog.Bind(wx.EVT_BUTTON, self.ok, ok);
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        dialog.SetSizer(sizer)
        dialog.Bind(wx.EVT_CLOSE, self.OnClose)
        dialog.CenterOnScreen();
        dialog.Show(True);

    def cancel(self, event):
        self.dialog.Close()

    def ok(self, event):
        val = self.field.GetValue()
        try:
            self.ival = int(val)
        except:
            return
        self.d.domain_id.convert_to_domain(self)
        self.dialog.Close()

    def OnClose(self, event):
        self.dialog.Destroy()

    def domain_cb(self, domain):
        domain.set_sel_rescan_time(self.ival)
        if (self.d.srscn != None):
            self.d.ui.set_item_text(self.d.srscn, "SEL Rescan Time",
                                    str(domain.get_sel_rescan_time()))
        
class DomainIPMBSet:
    def __init__(self, d):
        self.d = d;

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(-1, "Modify Value")
        self.d.ui.Bind(wx.EVT_MENU, self.modval, item)
        self.d.ui.PopupMenu(menu, self.d.ui.get_item_pos(eitem))
        menu.Destroy()

    def modval(self, event):
        dialog = wx.Dialog(None, -1, "Set IPMB Rescan Time")
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)
        
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(dialog, -1, "Value:")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        self.field = wx.TextCtrl(dialog, -1, str(self.d.ipmb_rescan_time))
        box.Add(self.field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(dialog, -1, "Cancel")
        dialog.Bind(wx.EVT_BUTTON, self.cancel, cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(dialog, -1, "Ok")
        dialog.Bind(wx.EVT_BUTTON, self.ok, ok);
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        dialog.SetSizer(sizer)
        dialog.Bind(wx.EVT_CLOSE, self.OnClose)
        dialog.CenterOnScreen();
        dialog.Show(True);

    def cancel(self, event):
        self.dialog.Close()

    def ok(self, event):
        val = self.field.GetValue()
        try:
            self.ival = int(val)
        except:
            return
        self.d.domain_id.convert_to_domain(self)
        self.dialog.Close()

    def OnClose(self, event):
        self.dialog.Destroy()

    def domain_cb(self, domain):
        domain.set_ipmb_rescan_time(self.ival)
        if (self.d.srscn != None):
            self.d.ui.set_item_text(self.d.irscn, "IPMB Rescan Time",
                                    str(domain.get_ipmb_rescan_time()))

class DomainConnection:
    def __init__(self):
        self.contype = ""
        self.address = ""
        self.port = ""
        self.username = ""
        self.password = ""
        self.privilege = ""
        self.authtype = ""
        self.auth_alg = ""
        self.integ_alg = ""
        self.conf_alg = ""
        self.bmc_key = ""
        self.address2 = ""
        self.port2 = ""
        self.hacks = [ ]
        self.lookup_uses_priv = False

    def SetType(self, contype):
        self.contype = contype

    def SetAddress(self, addr):
        self.address = addr

    def SetPort(self, port):
        self.port = port

    def SetUsername(self, username):
        self.username = username

    def SetPassword(self, password):
        self.password = password

    def SetPrivilege(self, value):
        if (value == 'default'):
            value = ''
        self.privilege = value
        
    def SetAuthtype(self, value):
        if (value == 'default'):
            value = ''
        self.authtype = value
        
    def SetAuth_alg(self, value):
        if (value == 'default'):
            value = ''
        self.auth_alg = value
        
    def SetInteg_alg(self, value):
        if (value == 'default'):
            value = ''
        self.integ_alg = value
        
    def SetConf_alg(self, value):
        if (value == 'default'):
            value = ''
        self.conf_alg = value
        
    def SetBmc_key(self, value):
        self.bmc_key = value
        
    def SetAddress2(self, value):
        self.address2 = value
        
    def SetPort2(self, value):
        self.port2 = value
        
    def AddHack(self, value):
        self.hacks.append(value)
        
    def AddHacks(self, values):
        self.hacks.extend(values.split())
        
    def Lookup_uses_priv(self, value):
        self.lookup_uses_priv = value

    def Valid(self):
        if (self.contype == "smi"):
            return (self.port != "")
        elif (self.contype == "lan"):
            return (self.address != "")
        else:
            return False

    def FillinConAttr(self, attr):
        print "9.1"
        if (self.contype == "smi"):
            print "9.2"
            print "9.3: " + self.port
            if (self.port == ""):
                raise InvalidDomainInfo("No port specified")
            print "9.3"
            attr.extend([ "smi", str(self.port) ])
            print "9.4"
        elif (self.contype == "lan"):
            if (self.address == ""):
                raise InvalidDomainInfo("No address specified")
            attr.append("lan")
            if (self.port != ""):
                attr.extend(["-p", self.port])
            if (self.username != ""):
                attr.extend(["-U", self.username])
            if (self.password != ""):
                attr.extend(["-P", self.password])
            if (self.authtype != ""):
                attr.extend(["-A", self.authtype])
            if (self.privilege != ""):
                attr.extend(["-L", self.privilege])
            if (self.auth_alg != ""):
                attr.extend(["-Ra", self.auth_alg])
            if (self.integ_alg != ""):
                attr.extend(["-Ri", self.integ_alg])
            if (self.conf_alg != ""):
                attr.extend(["-Rc", self.conf_alg])
            if (self.bmc_key != ""):
                attr.extend(["-Rk", self.bmc_key])
            if (self.lookup_uses_priv):
                attr.append("-Rl")
            for h in self.hacks:
                attr.extend(["-H", h])
            if (self.address2 != ""):
                attr.append("-s")
                if (self.port2 != ""):
                    attr.extend(["-p2", self.port2])
            attr.append(self.address)
            if (self.address2 != ""):
                attr.append(self.address2)
        else:
            raise InvalidDomainInfo("Invalid connection type: " + self.contype)
        print "9.5"

    def getAttr(self):
        if (self.contype == ""):
            return None
        attrl = [ ("contype", self.contype) ]
        if (self.address != ""):
            attrl.append(("address", self.address))
        if (self.port != ""):
            attrl.append(("port", self.port))
        if (self.username != ""):
            attrl.append(("username", self.username))
        if (self.password != ""):
            attrl.append(("password", self.password))
        if (self.privilege != ""):
            attrl.append(("privilege", self.privilege))
        if (self.authtype != ""):
            attrl.append(("authtype", self.authtype))
        if (self.auth_alg != ""):
            attrl.append(("auth_alg", self.auth_alg))
        if (self.integ_alg != ""):
            attrl.append(("integ_alg", self.integ_alg))
        if (self.conf_alg != ""):
            attrl.append(("conf_alg", self.conf_alg))
        if (self.bmc_key != ""):
            attrl.append(("bmc_key", self.bmc_key))
        if (self.address2 != ""):
            attrl.append(("address2", self.address2))
            if (self.port2 != ""):
                attrl.append(("port2", self.port2))
        hlen = len(self.hacks)
        if (hlen > 0):
            hvals = self.hacks[0]
            for i in range(1, hlen):
                hvals = hvals + ' ' + self.hacks[i]
            attrl.append(("hacks", hvals))
        return attrl

    def restore(self, mainhandler, attrhash):
        if "contype" not in attrhash:
            return
        contype = str(attrhash["contype"])
        del attrhash["contype"]
        self.SetType(contype)
        
        for attr in attrhash.items():
            attrn = str(attr[0])
            value = str(attr[1])
            if (attrn == "password"):
                self.SetPassword(value)
            elif (attrn == "username"):
                self.SetUsername(value)
            elif (attrn == "address"):
                self.SetAddress(value)
            elif (attrn == "port"):
                self.SetPort(value)
            elif (attrn == "privilege"):
                self.SetPrivilege(value)
            elif (attrn == "authtype"):
                self.SetAuthtype(value)
            elif (attrn == "auth_alg"):
                self.SetAuth_alg(value)
            elif (attrn == "integ_alg"):
                self.SetInteg_alg(value)
            elif (attrn == "conf_alg"):
                self.SetConf_alg(value)
            elif (attrn == "bmc_key"):
                self.SetBmc_key(value)
            elif (attrn == "address2"):
                self.SetAddress2(value)
            elif (attrn == "port2"):
                self.SetPort2(value)
            elif (attrn == "hacks"):
                self.AddHacks(value)
            elif (attrn == "lookup_uses_priv"):
                self.Lookup_uses_priv(True)

class Domain:
    def __init__(self, mainhandler, name):
        if (mainhandler.domains.has_key(name)):
            raise InvalidDomainInfo("Domain name already exists")
        self.name = name
        self.mainhandler = mainhandler
        self.ui = mainhandler.ui
        self.entities = { }
        self.mcs = { }

        self.connection = [ DomainConnection(), DomainConnection() ]

        self.updater = DomainRefreshData(self)
        self.domain_id = None
        mainhandler.domains[name] = self
        
        self.ui.add_domain(self)
        self.ipmb_rescan_time = 0
        self.sel_rescan_time = 0
        self.irscn = self.ui.prepend_item(self, "IPMB Rescan Time", None,
                                          DomainIPMBSet(self))
        self.srscn = self.ui.prepend_item(self, "SEL Rescan Time", None,
                                          DomainSelSet(self))
        self.dguid = self.ui.prepend_item(self, "GUID", None)
        self.dtype = self.ui.prepend_item(self, "Type", None)

    def __str__(self):
        return self.name

    def getTag(self):
        return "domain";

    def SaveInfo(self, doc, elem):
        c1 = doc.createElement("connection")
        elem.setAttribute("name", self.name)
        attrs = self.connection[0].getAttr()
        for attr in attrs:
            c1.setAttribute(attr[0], attr[1])
        elem.appendChild(c1)
        if self.connection[1].Valid():
            c2 = doc.createElement("connection")
            attrs = self.connections[1].getAttr()
            for attr in attrs:
                c2.setAttribute(attr[0], attr[1])
            elem.appendChild(c2)

    def DoUpdate(self):
        if (self.domain_id != None):
            self.domain_id.convert_to_domain(self.updater)

    def HandleExpand(self, event):
        self.DoUpdate()

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(-1, "Close")
        self.ui.Bind(wx.EVT_MENU, self.CloseMenuHandler, item)
        self.ui.PopupMenu(menu, self.ui.get_item_pos(eitem))
        menu.Destroy()

    def CloseMenuHandler(self, event):
        self.remove()

    def Connect(self):
        attr = [ ]
        print "1"
        self.connection[0].FillinConAttr(attr)
        print "1.1"
        if self.connection[1].Valid():
            print "1.2"
            self.connection[1].FillinConAttr(attr)
        #print str(attr)
        print "2"
        self.already_up = False
        self.domain_id = OpenIPMI.open_domain2(self.name, attr, self, self)
        print "3"
        if (self.domain_id == None):
            raise InvalidDomainInfo("Open domain failed, invalid parms")
        print "4"

    def domain_up_cb(self, domain):
        self.already_up = True;
        self.ui.set_item_active(self.treeroot)

    def conn_change_cb(self, domain, err, connum, portnum, connected):
        if (self.already_up):
            if (connected):
                self.ui.set_item_active(self.treeroot)
            else:
                self.ui.set_item_inactive(self.treeroot)
    
    def connected(self, domain):
        domain.add_entity_update_handler(self)
        domain.add_mc_update_handler(self)
        DomainRefreshData(self)

    def find_or_create_entity(self, entity):
        ename = entity.get_name()
        if (ename in self.entities):
            return self.entities[ename];
        else:
            return _entity.Entity(self, entity)
        
    def entity_update_cb(self, op, domain, entity):
        if (op == "added"):
            e = self.find_or_create_entity(entity)
            entity.add_sensor_update_handler(e)
            entity.add_control_update_handler(e)
        elif (op == "removed"):
            self.entities[entity.get_name()].remove()
        
    def mc_update_cb(self, op, domain, mc):
        if (op == "added"):
            _mc.MC(self, mc)
        elif (op == "removed"):
            self.entities[mc.get_name()].remove()
        
    def domain_cb(self, domain):
        domain.close(self)

    def domain_close_done_cb(self):
        pass
        
    def remove(self):
        if (self.domain_id != None):
            self.domain_id.convert_to_domain(self)
        self.mainhandler.domains.pop(self.name);
        self.ui.remove_domain(self)
        
class _DomainRestore(_saveprefs.RestoreHandler):
    def __init__(self):
        _saveprefs.RestoreHandler.__init__(self, "domain")

    def restore(self, mainhandler, node):
        print "A"
        name = str(node.getAttribute("name"));
        if (name == ""):
            return
        d = Domain(mainhandler, name)
        cnum = 0
        print "B"
        for c in node.childNodes:
            if ((c.nodeType == c.ELEMENT_NODE)
                and (c.nodeName == "connection")):
                attrhash = { }
                for i in range(0, c.attributes.length):
                    attr = c.attributes.item(i)
                    attrhash[attr.nodeName] = attr.nodeValue
                d.connection[cnum].restore(mainhandler, attrhash)
                if (cnum < 1):
                    cnum = 1;
        try:
            print "B1"
            d.Connect()
            print "B2"
        except InvalidDomainInfo, e:
            d.remove()
            print "Error making domain connection for " + name + ": " + str(e)
        print "C"

_DomainRestore()
