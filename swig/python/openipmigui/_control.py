
import OpenIPMI

class ControlRefreshData:
    def __init__(self, c):
        self.c = c

    def control_cb(self, control):
        control.get_val(self.c)

class ControlSet:
    def __init__(self, c):
        self.c = c;

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(-1, "Modify Value")
        self.d.ui.Bind(wx.EVT_MENU, self.modval, item)
        self.d.ui.PopupMenu(menu, self.d.ui.get_item_pos(eitem))
        menu.Destroy()

    def modval(self, event):
        dialog = wx.Dialog(None, -1, "Set Control Values")
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)
        sizer2 = wx.BoxSizer(wx.VERTICAL)
        
        self.values = scrolled.ScrolledPanel(self, -1, size=wx.Size(400, 400))
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(dialog, -1, "Value(s):")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        box2 = wx.BoxSizer(wx.VERTICAL)
        self.fields = [ ]
        for i in range(0, self.c.num_vals):
            if (i >= len(self.c.vals)):
                v = '0'
            else:
                v = self.c.vals[i]
            self.fields[i] = wx.TextCtrl(dialog, -1, v)
            box2.Add(self.fields[i], 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        box.Add(box2, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
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
        
class Control:
    def __init__(self, e, control):
        self.e = e
        self.name = control.get_name()
        self.control_id = control.get_id()
        self.ui = e.ui;
        self.updater = ControlRefreshData(self)
        self.vals = [ ]
        self.ui.add_control(self.e, self)
        self.num_vals = control.get_num_vals();

    def __str__(self):
        return self.name

    def DoUpdate(self):
        self.control_id.convert_to_control(self.updater)

    def control_get_val_cb(self, control, err, vals):
        self.num_vals = control.get_num_vals();
        self.vals = vals
        self.ui.set_item_text(self.treeroot, str(self), str(vals))
        
    def remove(self):
        self.e.controls.pop(self.name)
        self.ui.remove_control(self)

