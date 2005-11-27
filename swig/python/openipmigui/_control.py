
import OpenIPMI
import wx
import wx.lib.scrolledpanel as scrolled

class ControlRefreshData:
    def __init__(self, c):
        self.c = c

    def control_cb(self, control):
        if (self.c.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            control.identifier_get_val(self.c)
        elif (self.c.setting_light):
            control.get_light(self.c)
        else:
            control.get_val(self.c)

class ControlSet:
    def __init__(self, c):
        self.c = c;

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(-1, "Modify Value")
        self.c.ui.Bind(wx.EVT_MENU, self.modval, item)
        self.c.ui.PopupMenu(menu, self.c.ui.get_item_pos(eitem))
        menu.Destroy()

    def modval(self, event):
        dialog = wx.Dialog(None, -1, "Set Control Values",
                           size=wx.Size(300, 300))
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer2 = wx.BoxSizer(wx.VERTICAL)
        
        self.values = scrolled.ScrolledPanel(dialog, -1,
                                             size=wx.Size(300, 200))
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(self.values, -1, "Value(s):")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        box2 = wx.BoxSizer(wx.VERTICAL)
        self.fields = [ ]
        for i in range(0, self.c.num_vals):
            if (i >= len(self.c.vals)):
                v = '0'
            else:
                v = str(self.c.vals[i])
            field = wx.TextCtrl(self.values, -1, v)
            self.fields.append(field)
            box2.Add(field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        box.Add(box2, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        self.values.SetSizer(box)
        sizer.Add(self.values, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
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
        self.ival = [ ]
        try:
            for f in self.fields:
                val = f.GetValue()
                self.ival.append(int(val))
        except:
            return
        self.c.control_id.convert_to_control(self)
        self.dialog.Close()

    def OnClose(self, event):
        self.dialog.Destroy()

    def control_cb(self, control):
        if (self.c.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            control.identifier_set_val(self.ival)
        else:
            control.set_val(self.ival)
        
class LightSet:
    def __init__(self, c):
        self.c = c;

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(-1, "Modify Value")
        self.c.ui.Bind(wx.EVT_MENU, self.modval, item)
        self.c.ui.PopupMenu(menu, self.c.ui.get_item_pos(eitem))
        menu.Destroy()

    def modval(self, event):
        dialog = wx.Dialog(None, -1, "Set Light Values",
                           size=wx.Size(300, 300))
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer2 = wx.BoxSizer(wx.VERTICAL)
        
        self.values = scrolled.ScrolledPanel(dialog, -1,
                                             size=wx.Size(300, 200))
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(self.values, -1, "Value(s):")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        box2 = wx.BoxSizer(wx.VERTICAL)
        self.fields = [ ]
        for i in range(0, self.c.num_vals):
            if (i >= len(self.c.vals)):
                v = '0'
            else:
                v = str(self.c.vals[i])
            field = wx.TextCtrl(self.values, -1, v)
            self.fields.append(field)
            box2.Add(field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        box.Add(box2, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        self.values.SetSizer(box)
        sizer.Add(self.values, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        
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
        self.ival = [ ]
        try:
            for f in self.fields:
                val = f.GetValue()
                self.ival.append(int(val))
        except:
            return
        self.c.control_id.convert_to_control(self)
        self.dialog.Close()

    def OnClose(self, event):
        self.dialog.Destroy()

    def control_cb(self, control):
        if (self.c.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            control.identifier_set_val(self.ival)
        else:
            control.set_val(self.ival)
        
class Control:
    def __init__(self, e, control):
        self.e = e
        self.name = control.get_name()
        self.control_id = control.get_id()
        self.ui = e.ui;
        self.updater = ControlRefreshData(self)
        self.vals = [ ]
        self.ui.add_control(self.e, self)
        self.control_type = control.get_type()
        if (self.control_type == OpenIPMI.CONTROL_IDENTIFIER):
            self.num_vals = control.identifier_get_max_length();
        else:
            self.num_vals = control.get_num_vals();

        if ((self.control_type == OpenIPMI.CONTROL_LIGHT)
            and (control.light_set_with_setting())):
            self.setting_light = True
            self.has_local_control = control.light_has_local_control()
            self.colors = [ ]
            for i in range (0, OpenIPMI.CONTROL_NUM_COLORS):
                if control.light_is_color_supported(i):
                    self.colors.append(OpenIPMI.color_string(i))
                else:
                    self.colors.append(None)
        else:
            self.setting_light = False

        self.is_settable = control.is_settable()
        self.is_readable = control.is_readable()
        if (self.is_settable):
            if (self.setting_light):
                self.setter = LightSet(self)
            else:
                self.setter = ControlSet(self)
        else:
            self.setter = None

    def __str__(self):
        return self.name

    def DoUpdate(self):
        if (self.is_readable):
            self.control_id.convert_to_control(self.updater)

    def HandleMenu(self, event):
        if (self.setter != None):
            self.setter.HandleMenu(event)
        
    def control_get_val_cb(self, control, err, vals):
        if (err != 0):
            self.ui.set_item_text(self.treeroot, str(self), None)
            return
        self.num_vals = control.get_num_vals();
        self.vals = vals
        self.ui.set_item_text(self.treeroot, str(self), str(vals))
        
    def control_get_id_cb(self, control, err, val):
        if (err != 0):
            self.ui.set_item_text(self.treeroot, str(self), None)
            return
        self.num_vals = control.identifier_get_max_length();
        self.val = val
        self.ui.set_item_text(self.treeroot, str(self), str(val))

    def control_get_light_cb(self, control, err, vals):
        if (err != 0):
            self.ui.set_item_text(self.treeroot, str(self), None)
            return
        self.num_vals = control.identifier_get_max_length();
        self.vals = vals
        self.ui.set_item_text(self.treeroot, str(self), str(vals))

    def remove(self):
        self.e.controls.pop(self.name)
        self.ui.remove_control(self)
