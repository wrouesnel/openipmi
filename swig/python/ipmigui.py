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

class OpenDomainDialog(wx.Dialog):
    def __init__(self, mainhandler):
        wx.Dialog.__init__(self, None, -1, "Open Domain")

        self.mainhandler = mainhandler

        self.sizer = wx.BoxSizer(wx.VERTICAL)
        
        box, self.name = self.newField("Domain name")
        self.sizer.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 2)
        
        self.contype = wx.RadioBox(self, -1, "Domain Type",
                                   wx.DefaultPosition, wx.DefaultSize,
                                   [ 'smi', 'lan'], 2, wx.RA_SPECIFY_COLS)
        self.Bind(wx.EVT_RADIOBOX, self.selectType, self.contype);
        self.sizer.Add(self.contype, 0, wx.ALIGN_CENTRE, 2)

        self.smiInfo = wx.Panel(self, -1)
        self.smiInfo_sizer = wx.BoxSizer(wx.VERTICAL)
        box, self.smiNum = self.newField("SMI Number", "0",
                                         parent=self.smiInfo)
        self.smiInfo_sizer.Add(box, 0, wx.LEFT | wx.ALL, 2)
        self.sizer.Add(self.smiInfo, 0, wx.ALIGN_CENTRE, 2)
        self.smiInfo.Show(True)

        self.lanInfo = wx.Panel(self, -1)
        self.lanInfo_sizer = wx.BoxSizer(wx.VERTICAL)
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        box, self.address = self.newField("Address", parent=self.lanInfo)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        box, self.port = self.newField("Port", "623", parent=self.lanInfo)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.lanInfo_sizer.Add(bbox, 0, wx.LEFT | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        box, self.username = self.newField("Username", parent=self.lanInfo)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        box, self.password = self.newField("Password", parent=self.lanInfo,
                                           style=wx.TE_PASSWORD)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.lanInfo_sizer.Add(bbox, 0, wx.LEFT | wx.ALL, 2)
        self.lanInfo.SetSizer(self.lanInfo_sizer)
        self.sizer.Add(self.lanInfo, 0, wx.ALIGN_CENTRE, 2)
        self.lanInfo.Show(False)

        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(self, -1, "Cancel")
        self.Bind(wx.EVT_BUTTON, self.cancel, cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(self, -1, "Ok")
        self.Bind(wx.EVT_BUTTON, self.ok, ok);
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.status = wx.StatusBar(self)
        self.sizer.Add(self.status, 0, wx.ALIGN_LEFT | wx.ALL, 2)
        
        self.SetSizer(self.sizer)

        self.Bind(wx.EVT_CLOSE, self.OnClose)
        

    def newField(self, name, initval="", parent=None, style=0):
        if parent == None:
            parent = self
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(parent, -1, name + ":")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        field = wx.TextCtrl(parent, -1, initval, style=style);
        box.Add(field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        return box, field;

    def selectType(self, event):
        if event.GetInt() == 0:
            self.lanInfo.Show(False)
            self.smiInfo.Show(True)
        else:
            self.smiInfo.Show(False)
            self.lanInfo.Show(True)
        self.Layout()

    def cancel(self, event):
        self.Close(True)


    def ok(self, event):
        name = str(self.name.GetValue())
        if (name == ""):
            self.status.SetStatusText("No name specified")
            return
        contype = self.contype.GetSelection()
        try:
            d = Domain(self.mainhandler, name);
            if (contype == 0):
                d.SetType("smi")
                d.SetPort(str(self.port.GetValue()))
            elif (contype == 1):
                d.SetType("lan")
                d.SetAddress(str(self.address.GetValue()))
                d.SetPort(str(self.port.GetValue()))
                d.SetUsername(str(self.username.GetValue()))
                d.SetPassword(str(self.password.GetValue()))
            d.Connect()
        except InvalidDomainInfo, e:
            d.remove()
            self.status.SetStatusText(e)
            return
        except Exception, e:
            d.remove()
            self.status.SetStatusText("Unknown error: " + str(e))
            raise e
            return
            
        self.Close(True)

    def OnClose(self, event):
        self.Destroy()

class IPMITreeCtrl(wx.TreeCtrl):
    def __init__(self, parent):
        wx.TreeCtrl.__init__(self, parent)

    def OnCompareItems(self, item1, item2):
        t1 = self.GetItemText(item1)
        t2 = self.GetItemText(item2)
        self.log.WriteText('compare: ' + t1 + ' <> ' + t2 + '\n')
        if t1 < t2: return -1
        if t1 == t2: return 0
        return 1

class IPMICloser:
    def __init__(self, ui, count):
        self.ui = ui
        self.count = count
    
    def domain_cb(self, domain):
        domain.close(self)

    def domain_close_done_cb(self):
        self.count = self.count - 1
        if (self.count == 0):
            ui.Close(True)

class IPMIGUI(wx.Frame):
    def __init__(self, mainhandler):
        wx.Frame.__init__(self, None, 01, "IPMI GUI")

        self.mainhandler = mainhandler
        
        menubar = wx.MenuBar()
        
        filemenu = wx.Menu()
        filemenu.Append(wx.ID_EXIT, "E&xit\tCtrl-Q", "Exit")
        self.Bind(wx.EVT_MENU, self.quit, id=wx.ID_EXIT);
        item = filemenu.Append(-1, "&Open Domain\tCtrl-O", "Open Domain")
        self.Bind(wx.EVT_MENU, self.openDomain, item);
        menubar.Append(filemenu, "&File")
        
        self.SetMenuBar(menubar)

        box = wx.BoxSizer(wx.HORIZONTAL)

        isz = (16, 16)
        self.tree = IPMITreeCtrl(self)
        self.treeroot = self.tree.AddRoot("Domains")
        self.tree.SetPyData(self.treeroot, None)
        box.Add(self.tree, 1,
                wx.ALIGN_LEFT | wx.ALIGN_TOP | wx.ALIGN_BOTTOM | wx.GROW,
                0)

        self.logwindow = wx.TextCtrl(self, -1,
                                     style=(wx.TE_MULTILINE
                                            | wx.TE_READONLY
                                            | wx.HSCROLL))
        box.Add(self.logwindow, 1,
                wx.ALIGN_RIGHT | wx.ALIGN_TOP | wx.ALIGN_BOTTOM | wx.GROW,
                0)
        self.logcount = 0
        self.maxloglines = 1000

        self.SetSizer(box);

        self.tree.Bind(wx.EVT_TREE_ITEM_MENU, self.TreeMenu)
        self.tree.Bind(wx.EVT_TREE_ITEM_EXPANDED, self.TreeExpanded)

        self.Show(True)

    def quit(self, event):
        self.closecount = len(self.mainhandler.domains)
        if (self.closecount == 0):
            self.Close(True)
            return
        closer = IPMICloser(self, self.closecount)
        for v in self.mainhandler.domains.itervalues():
            v.domain_id.convert_to_domain(closer)

    def openDomain(self, event):
        dialog = OpenDomainDialog(self.mainhandler)
        dialog.CenterOnScreen();
        dialog.Show(True);

    def new_log(self, log):
        newlines = log.count('\n') + 1
        self.logwindow.AppendText(log + "\n")
        self.logcount += newlines
        while (self.logcount > self.maxloglines):
            end = self.logwindow.GetLineLength(0)
            self.logwindow.Remove(0, end+1)
            self.logcount -= 1

    def add_domain(self, d):
        d.treeroot = self.tree.AppendItem(self.treeroot, str(d))
        self.tree.SetPyData(d.treeroot, d)
        d.entityroot = self.tree.AppendItem(d.treeroot, "Entities")
        d.mcroot = self.tree.AppendItem(d.treeroot, "MCs")
        self.tree.Expand(self.treeroot)

    def prepend_item(self, o, name, value, data=None):
        if (value == None):
            item = self.tree.PrependItem(o.treeroot, name + ":")
            self.tree.SetItemTextColour(item, wx.LIGHT_GREY)
        else:
            item = self.tree.PrependItem(o.treeroot, name + ":\t" + value)
            self.tree.SetItemTextColour(item, wx.BLACK)
        self.tree.SetPyData(item, data)
        return item

    def append_item(self, o, name, value, data=None):
        if (value == None):
            item = self.tree.AppendItem(o.treeroot, name + ":")
            self.tree.SetItemTextColour(item, wx.LIGHT_GREY)
        else:
            item = self.tree.AppendItem(o.treeroot, name + ":\t" + value)
            self.tree.SetItemTextColour(item, wx.BLACK)
        self.tree.SetPyData(item, data)
        return item

    def set_item_text(self, item, name, value):
        if (value == None):
            self.tree.SetItemText(item, name + ":")
            self.tree.SetItemTextColour(item, wx.LIGHT_GREY)
        else:
            self.tree.SetItemText(item, name + ":\t" + value)
            self.tree.SetItemTextColour(item, wx.BLACK)

    def get_item_pos(self, item):
        rect = self.tree.GetBoundingRect(item)
        if (rect == None):
            return None
        return wx.Point(rect.GetLeft(), rect.GetBottom())

    def TreeMenu(self, event):
        item = event.GetItem()
        data = self.tree.GetPyData(item)
        if (data != None) and (hasattr(data, "HandleMenu")):
            data.HandleMenu(event)

    # FIXME - expand of parent doesn't affect children...
    def TreeExpanded(self, event):
        item = event.GetItem()
        data = self.tree.GetPyData(item)
        if (data != None) and (hasattr(data, "HandleExpand")):
            data.HandleExpand(event)

    def remove_domain(self, d):
        if (hasattr(d, "treeroot")):
            self.tree.Delete(d.treeroot)

    def add_entity(self, d, e):
        e.treeroot = self.tree.AppendItem(d.entityroot, str(e))
        e.sensorroot = self.tree.AppendItem(e.treeroot, "Sensors")
        e.controlroot = self.tree.AppendItem(e.treeroot, "Controls")
        self.tree.SetPyData(e.treeroot, None)
        self.tree.SetPyData(e.sensorroot, None)
        self.tree.SetPyData(e.controlroot, None)
    
    def remove_entity(self, e):
        if (hasattr(e, "treeroot")):
            self.tree.Delete(e.treeroot)

    def add_mc(self, d, m):
        m.treeroot = self.tree.AppendItem(d.mcroot, m.name)
        self.tree.SetPyData(m.treeroot, None)

    def remove_mc(self, m):
        if (hasattr(m, "treeroot")):
            self.tree.Delete(m.treeroot)

    def add_sensor(self, e, s):
        s.treeroot = self.tree.AppendItem(e.sensorroot, str(s))

    def remove_sensor(self, s):
        if (hasattr(s, "treeroot")):
            self.tree.Delete(s.treeroot)

    def add_control(self, e, c):
        c.treeroot = self.tree.AppendItem(e.controlroot, str(c))

    def remove_control(self, c):
        if (hasattr(c, "treeroot")):
            self.tree.Delete(c.treeroot)

class Sensor:
    def __init__(self, e, sensor):
        self.e = e
        self.name = sensor.get_name()
        self.sensor_id = sensor.get_id()
        self.ui = e.ui
        ui = self.ui
        ui.add_sensor(self.e, self)
        self.valueitem = ui.append_item(self, "Value", None)
        sensor.get_value(self)

    def __str__(self):
        return self.name

    def remove(self):
        self.e.sensors.pop(self.name)
        self.ui.remove_sensor(self)

    def threshold_reading_cb(self, sensor, err, raw_set, raw, value_set,
                             value, states):
        if (err):
            self.ui.set_item_text(self.valueitem, "Value", None)
            return
        v = ""
        if (value_set):
            v = v + str(value)
        if (raw_set):
            v = v + "(" + str(raw) + ")"
        v = v + ": " + states
        self.ui.set_item_text(self.valueitem, "Value", v)
        
    def discrete_states_cb(self, sensor, err, states):
        if (err):
            self.ui.set_item_text(self.valueitem, "Value", None)
            return
        self.ui.set_item_text(self.valueitem, "Value", states)
        

class Control:
    def __init__(self, e, control):
        self.e = e
        self.name = control.get_name()
        self.control_id = control.get_id()
        self.ui = e.ui;
        self.ui.add_control(self.e, self)

    def __str__(self):
        return self.name

    def remove(self):
        self.e.controls.pop(self.name)
        self.ui.remove_control(self)

class Entity:
    def __init__(self, d, entity):
        self.d = d
        self.name = entity.get_name()
        self.entity_id = entity.get_id()
        d.entities[self.name] = self
        self.ui = d.ui
        self.ui.add_entity(self.d, self)
        self.sensors = { }
        self.controls = { }

    def __str__(self):
        return self.name

    def remove(self):
        self.d.entities.pop(self.name)
        self.ui.remove_entity(self)

    def entity_sensor_update_cb(self, op, entity, sensor):
        if (op == "added"):
            e = Sensor(self, sensor)
        elif (op == "removed"):
            self.sensors[sensor.get_name()].remove()

    def entity_control_update_cb(self, op, entity, control):
        if (op == "added"):
            e = Control(self, control)
        elif (op == "removed"):
            self.controls[control.get_name()].remove()

class MC:
    def __init__(self, d, mc):
        self.d = d
        self.name = mc.get_name()
        d.mcs[self.name] = self
        self.ui = d.ui;
        self.ui.add_mc(self.d, self)

    def remove(self):
        self.d.mcs.pop(self.name)
        self.ui.remove_mc(self)


class InvalidDomainInfo(Exception):
    def __init__(self, value):
        self.value = value
    def __str__(self):
        return repr(self.value)


class DomainRefreshData:
    def __init__(self, d):
        self.d = d;

    def domain_cb(self, domain):
        if (self.d.irscn != None):
            self.d.ui.set_item_text(self.d.irscn,
                                    "IPMB Rescan Time",
                                    str(domain.get_ipmb_rescan_time()))
        if (self.d.srscn != None):
            self.d.ui.set_item_text(self.d.srscn, "SEL Rescan Time",
                                    str(domain.get_sel_rescan_time()))
        if (self.d.dguid != None):
            self.d.ui.set_item_text(self.d.dguid, "GUID",
                                    domain.get_guid())
        if (self.d.dtype != None):
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
        self.field = wx.TextCtrl(dialog, -1, "");
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
        

class Domain:
    def __init__(self, mainhandler, name):
        if (mainhandler.domains.has_key(name)):
            raise InvalidDomainInfo("Domain name already exists")
        self.name = name
        self.mainhandler = mainhandler
        self.ui = mainhandler.ui
        self.entities = { }
        self.mcs = { }
        self.contype = ""
        self.address = ""
        self.port = ""
        self.username = ""
        self.password = ""
        self.irscn = None
        self.srscn = None
        self.dguid = None
        self.dtype = None
        self.domain_id = None
        mainhandler.domains[name] = self
        self.ui.add_domain(self)

    def __str__(self):
        return self.name

    def HandleExpand(self, event):
        if (self.domain_id != None):
            self.domain_id.convert_to_domain(DomainRefreshData(self))

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

    def Connect(self):
        if (self.contype == "smi"):
            if (self.port == ""):
                raise InvalidDomainInfo("No port specified")
            self.domain_id = OpenIPMI.open_domain2(self.name,
                                                   ["smi", self.port])
        elif (self.contype == "lan"):
            if (self.address == ""):
                raise InvalidDomainInfo("No address specified")
            attr = [ "lan" ]
            if (self.port != ""):
                attr.extend(["-p", self.port])
            if (self.username != ""):
                attr.extend(["-U", self.username])
            if (self.password != ""):
                attr.extend(["-P", self.password])
            attr.append(self.address)
            self.domain_id = OpenIPMI.open_domain2(self.name, attr)
        else:
            raise InvalidDomainInfo("Invalid connection type: " + self.contype)

    def connected(self, domain):
        domain.add_entity_update_handler(self)
        domain.add_mc_update_handler(self)
        self.irscn = self.ui.prepend_item(self, "IPMB Rescan Time",
                                          str(domain.get_ipmb_rescan_time()))
        self.srscn = self.ui.prepend_item(self, "SEL Rescan Time",
                                          str(domain.get_sel_rescan_time()),
                                          DomainSelSet(self))
        self.dguid = self.ui.prepend_item(self, "GUID", domain.get_guid())
        self.dtype = self.ui.prepend_item(self, "Type", domain.get_type())

    def entity_update_cb(self, op, domain, entity):
        if (op == "added"):
            e = Entity(self, entity)
            entity.add_sensor_update_handler(e)
            entity.add_control_update_handler(e)
        elif (op == "removed"):
            self.entities[entity.get_name()].remove()
        
    def mc_update_cb(self, op, domain, mc):
        if (op == "added"):
            MC(self, mc)
        elif (op == "removed"):
            self.entities[mc.get_name()].remove()
        
    def domain_cb(self, domain):
        domain.close(self)

    def domain_close_done_cb(self):
        pass
        
    def remove(self):
        if (hasattr(self, domain_id)):
            self.domain_id.convert_to_domain(self)
        self.mainhandler.domains.pop(self.name);
        self.ui.remove_domain(self)
        

class DomainHandler:
    def __init__(self):
        self.domains = { };

    def domain_change_cb(self, op, domain):
        if (op == "added"):
            self.domains[domain.get_name()].connected(domain)
        elif (op == "removed"):
            self.domains[domain.get_name()].remove()

    def SetUI(self, ui):
        self.ui = ui;

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
    
    mainhandler = DomainHandler()

    ui = IPMIGUI(mainhandler)
    mainhandler.SetUI(ui)
    
    app.SetTopWindow(ui)

    OpenIPMI.add_domain_change_handler(mainhandler)
    OpenIPMI.set_log_handler(mainhandler)

    try:
        fname = os.path.join(os.environ['HOME'], '.ipmigui.startup')
        f = open(fname, 'r')
        line = f.readline()
        while (line != ''):
            try:
                l = line.split(';')
                name = l[0]
                del l[0]
                contype = l[0]
                del l[0]
                d = Domain(mainhandler, name)
                try:
                    if (contype == 'smi'):
                        d.SetType("smi")
                        d.SetPort(str(l[0]))
                    elif (contype == 'lan'):
                        d.SetType("lan")
                        d.SetAddress(str(l[0]))
                        d.SetPort(str(l[1]))
                        d.SetUsername(str(l[2]))
                        d.SetPassword(str(l[3]))
                    d.Connect()
                except:
                    d.remove()
            except:
                pass
            line = f.readline()
    except:
        pass
    
    app.MainLoop()
    OpenIPMI.set_log_handler(DummyLogHandler())
    OpenIPMI.shutdown_everything()
