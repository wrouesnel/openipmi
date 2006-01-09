# _mc_user.py
#
# openipmi GUI handling for MC users
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
import wx
import wx.gizmos as gizmos
import _oi_logging
import _mc_lanparm

id_st = 900

class BoolSetter:
    def __init__(self, mcusers, user, item, setter):
        self.mcusers = mcusers
        self.item = item
        self.setter = setter
        self.user = user
        mcusers.tree.SetPyData(item, self)
        return
    
    def HandleMenu(self, event, eitem, point):
        menu = wx.Menu();
        item = menu.Append(id_st+1, "Toggle Value")
        wx.EVT_MENU(menu, id_st+1, self.togglevalue)
        self.mcusers.tree.PopupMenu(menu, point)
        menu.Destroy()
        return

    def togglevalue(self, event):
        val = str(self.mcusers.tree.GetItemText(self.item, 1))
        if (val == "True") or (val == "true"):
            val = "false"
            bval = 0
        else:
            val = "true"
            bval = 1
            pass
        rv = self.setter(bval)
        if (rv):
            mcusers.errstr.SetStatusText("Could not toggle value: "
                                        + OpenIPMI.get_error_string(rv), 0)
            return
        self.user.changed = True
        self.mcusers.tree.SetItemText(self.item, val, 1);
        return

    pass

class IntSetter:
    def __init__(self, mcusers, user, item, setter, name, currval):
        self.mcusers = mcusers
        self.item = item
        self.setter = setter
        self.name = name
        self.currval = currval
        self.user = user
        mcusers.tree.SetPyData(item, self)
        return
    
    def HandleMenu(self, event, eitem, point):
        menu = wx.Menu();
        item = menu.Append(id_st+10, "Modify Value")
        wx.EVT_MENU(menu, id_st+10, self.modval)
        self.mcusers.tree.PopupMenu(menu, point)
        menu.Destroy()
        return

    def modval(self, event):
        dialog = wx.Dialog(None, -1, "Set Value for " + self.name,
                           size=wx.Size(300, 300))
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)

        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(self.dialog, -1, "Value: ")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        self.field = wx.TextCtrl(self.dialog, -1, str(self.currval))
        box.Add(self.field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 5)

        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(dialog, -1, "Cancel")
        wx.EVT_BUTTON(dialog, cancel.GetId(), self.cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(dialog, -1, "Ok")
        wx.EVT_BUTTON(dialog, ok.GetId(), self.ok);
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
            val = int(val)
            pass
        except:
            mcusers.errstr.SetStatusText("Invalid integer value", 0)
            return
            
        rv = self.setter(val)
        if (rv):
            mcusers.errstr.SetStatusText("Could not set value: "
                                        + OpenIPMI.get_error_string(rv), 0)
            return
        self.user.changed = True
        self.mcusers.tree.SetItemText(self.item, str(val), 1)
        self.currval = val
        self.dialog.Close()
        return

    def OnClose(self, event):
        self.dialog.Destroy()
        self.dialog = None
        self.field = None
        return

    pass

class StrSetter:
    def __init__(self, mcusers, user, item, setter, name, currval, prompt):
        self.mcusers = mcusers
        self.item = item
        self.setter = setter
        self.name = name
        self.currval = currval
        self.user = user
        self.prompt = prompt
        mcusers.tree.SetPyData(item, self)
        return
    
    def HandleMenu(self, event, eitem, point):
        menu = wx.Menu();
        item = menu.Append(id_st+10, self.prompt)
        wx.EVT_MENU(menu, id_st+10, self.modval)
        self.mcusers.tree.PopupMenu(menu, point)
        menu.Destroy()
        return

    def modval(self, event):
        dialog = wx.Dialog(None, -1, self.prompt + " for " + self.name,
                           size=wx.Size(300, 300))
        self.dialog = dialog
        sizer = wx.BoxSizer(wx.VERTICAL)

        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(self.dialog, -1, "Value: ")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        self.field = wx.TextCtrl(self.dialog, -1, str(self.currval))
        box.Add(self.field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 5)

        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(dialog, -1, "Cancel")
        wx.EVT_BUTTON(dialog, cancel.GetId(), self.cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(dialog, -1, "Ok")
        wx.EVT_BUTTON(dialog, ok.GetId(), self.ok);
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
        rv = self.setter(str(val))
        if (rv):
            mcusers.errstr.SetStatusText("Could not set value: "
                                        + OpenIPMI.get_error_string(rv), 0)
            return
        self.user.changed = True
        self.mcusers.tree.SetItemText(self.item, str(val), 1)
        self.currval = val
        self.dialog.Close()
        return

    def OnClose(self, event):
        if (self.dialog):
            self.dialog.Destroy()
        self.dialog = None
        self.field = None
        return

    pass

class PrivSetter:
    def __init__(self, mcusers, user, item, setter):
        self.mcusers = mcusers
        self.item = item
        self.setter = setter
        self.user = user
        mcusers.tree.SetPyData(item, self)
        return
    
    def HandleMenu(self, event, eitem, point):
        menu = wx.Menu();
        item = menu.Append(id_st+20, "Callback")
        wx.EVT_MENU(menu, id_st+20, self.callback)
        item = menu.Append(id_st+21, "User")
        wx.EVT_MENU(menu, id_st+21, self.handleuser)
        item = menu.Append(id_st+22, "Operator")
        wx.EVT_MENU(menu, id_st+22, self.operator)
        item = menu.Append(id_st+23, "Admin")
        wx.EVT_MENU(menu, id_st+23, self.admin)
        item = menu.Append(id_st+24, "OEM")
        wx.EVT_MENU(menu, id_st+24, self.oem)
        self.mcusers.tree.PopupMenu(menu, point)
        menu.Destroy()
        return

    def setval(self, val):
        rv = self.setter(val)
        if (rv):
            mcusers.errstr.SetStatusText("Could not set value: "
                                        + OpenIPMI.get_error_string(rv), 0)
            return
        self.user.changed = True
        self.mcusers.tree.SetItemText(self.item, 
                                     OpenIPMI.privilege_string(val),
                                     1)
        return
        
    def callback(self, event):
        self.setval(OpenIPMI.PRIVILEGE_CALLBACK)
        return

    def handleuser(self, event):
        self.setval(OpenIPMI.PRIVILEGE_USER)
        return

    def operator(self, event):
        self.setval(OpenIPMI.PRIVILEGE_OPERATOR)
        return

    def admin(self, event):
        self.setval(OpenIPMI.PRIVILEGE_ADMIN)
        return

    def oem(self, event):
        self.setval(OpenIPMI.PRIVILEGE_OEM)
        return

    pass

def IntToBoolStr(v):
    if (v):
        return "true"
    else:
        return "false"
    return

class SetUserHandler:
    def __init__(self, mcusers, num):
        self.mcusers = mcusers
        self.num = num
        return

    def mc_channel_set_user_cb(self, mc, err):
        self.mcusers.user_set(mc, err, self.num)
        return

    pass

class MCUsers(wx.Dialog):
    def __init__(self, mc, channel, max_users, enabled_users, fixed_users,
                 users):
        wx.Dialog.__init__(self, None, -1, "User info for " + mc.get_name()
                           + " channel " + str(channel),
                           size=wx.Size(500, 600),
                           style=wx.RESIZE_BORDER)
        self.mc_id = mc.get_id()
        self.count = 0;
        self.users = users
        self.channel = channel
        self.in_save = False

        sizer = wx.BoxSizer(wx.VERTICAL)

        self.tree = gizmos.TreeListCtrl(self)
        self.tree.AddColumn("Name")
        self.tree.AddColumn("Value")
        self.tree.SetMainColumn(0)
        self.tree.SetColumnWidth(0, 300)
        self.tree.SetColumnWidth(1, 400)
        self.treeroot = self.tree.AddRoot("Users")

        sizer.Add(self.tree, 1, wx.GROW, 0);

        self.errstr = wx.StatusBar(self, -1)
        sizer.Add(self.errstr, 0, wx.ALIGN_CENTRE | wx.ALL, 5)

        box = wx.BoxSizer(wx.HORIZONTAL)
        save = wx.Button(self, -1, "Save")
        wx.EVT_BUTTON(self, save.GetId(), self.save)
        box.Add(save, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        cancel = wx.Button(self, -1, "Cancel")
        wx.EVT_BUTTON(self, cancel.GetId(), self.cancel)
        box.Add(cancel, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        item = self.tree.AppendItem(self.treeroot, "Max Users")
        self.tree.SetItemText(item, str(max_users), 1)
        item = self.tree.AppendItem(self.treeroot, "Enabled Users")
        self.tree.SetItemText(item, str(enabled_users), 1)
        item = self.tree.AppendItem(self.treeroot, "Fixed Users")
        self.tree.SetItemText(item, str(fixed_users), 1)
        
        for u in users:
            v = [ 0 ]
            rv = u.get_num(v)
            u.changed = False
            num = v[0]
            if (rv == 0):
                u.num = num
                us = self.tree.AppendItem(self.treeroot, str(num))
                nm = u.get_name()
                if (nm):
                    nm = str(nm)
                    self.tree.SetItemText(us, nm, 1)
                    pass
                else:
                    nm = ""
                    pass
                StrSetter(self, u, us, u.set_password_auto, "Password", "",
                          "Set Password")
                item = self.tree.AppendItem(us, "Name")
                self.tree.SetItemText(item, nm, 1)
                if (num > fixed_users):
                    StrSetter(self, u, item, u.set_name, "Name", nm,
                              "Modify Value")
                rv = u.get_enable(v)
                if (rv == 0):
                    s = IntToBoolStr(v[0])
                else:
                    s = "?"
                    pass
                item = self.tree.AppendItem(us, "Enabled")
                self.tree.SetItemText(item, s, 1)
                BoolSetter(self, u, item, u.set_enable)

                rv = u.get_link_auth_enabled(v)
                if (rv == 0):
                    s = IntToBoolStr(v[0])
                else:
                    s = "?"
                    pass
                item = self.tree.AppendItem(us, "Link Auth Enabled")
                self.tree.SetItemText(item, s, 1)
                BoolSetter(self, u, item, u.set_link_auth_enabled)

                rv = u.get_msg_auth_enabled(v)
                if (rv == 0):
                    s = IntToBoolStr(v[0])
                else:
                    s = "?"
                    pass
                item = self.tree.AppendItem(us, "Msg Auth Enabled")
                self.tree.SetItemText(item, s, 1)
                BoolSetter(self, u, item, u.set_msg_auth_enabled)

                rv = u.get_access_cb_only(v)
                if (rv == 0):
                    s = IntToBoolStr(v[0])
                else:
                    s = "?"
                    pass
                item = self.tree.AppendItem(us, "Access Callback Only")
                self.tree.SetItemText(item, s, 1)
                BoolSetter(self, u, item, u.set_access_cb_only)

                rv = u.get_privilege_limit(v)
                if (rv == 0):
                    s = OpenIPMI.privilege_string(v[0])
                else:
                    s = "?"
                    pass
                item = self.tree.AppendItem(us, "Privilege Limit")
                self.tree.SetItemText(item, s, 1)
                PrivSetter(self, u, item, u.set_privilege_limit)

                rv = u.get_session_limit(v)
                if (rv == 0):
                    s = str(v[0])
                else:
                    s = "?"
                    v[0] = 0
                    pass
                item = self.tree.AppendItem(us, "Session Limit")
                self.tree.SetItemText(item, s, 1)
                IntSetter(self, u, item, u.set_session_limit,
                          "Session Limit", v[0])
                pass
            pass

        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();
        wx.EVT_TREE_ITEM_RIGHT_CLICK(self.tree, -1, self.TreeMenu)
        self.tree.Expand(self.treeroot)
        self.SetSizer(sizer)
        self.Show(True)
        return

    def TreeMenu(self, event):
        eitem = event.GetItem()
        data = self.tree.GetPyData(eitem)
        if (data and hasattr(data, "HandleMenu")):
            rect = self.tree.GetBoundingRect(eitem)
            if (rect == None):
                point = None
            else:
                # FIXME - why do I have to add 25?
                point = wx.Point(rect.GetLeft(), rect.GetBottom()+25)
                pass
            data.HandleMenu(event, eitem, point)
            pass
        return

    def cancel(self, event):
        if (self.in_save):
            return
        self.Close()
        return
    
    def save(self, event):
        if (self.in_save):
            return
        self.mc_id.to_mc(self)
        return

    def mc_cb(self, mc):
        self.errnum = 0
        self.waitcount = 0
        self.errstr.SetFieldsCount(0)
        for u in self.users:
            if (u.changed):
                rv = mc.set_user(u, self.channel, u.num,
                                 SetUserHandler(self, u.num))
                if (rv):
                    self.errstr.SetFieldsCount(self.errnum+1)
                    self.errstr.SetStatusText("Error setting user "
                                              + str(u.num)  + ": "
                                              + OpenIPMI.get_error_string(rv),
                                              self.errnum)
                    self.errnum += 1
                else:
                    self.waitcount += 1
                    pass
                pass
            pass
        if ((self.errnum == 0) and (self.waitcount == 0)):
            self.Close()
        elif (self.waitcount > 0):
            self.in_save = True
        return

    def user_set(self, mc, err, num):
        if (err):
            self.errstr.SetFieldsCount(self.errnum+1)
            self.errstr.SetStatusText("Error setting user " + str(num) + ": "
                                      + OpenIPMI.get_error_string(err),
                                      self.errnum)
            self.errnum += 1
            pass
        self.waitcount -= 1
        if (self.waitcount <= 0):
            self.in_save = False;
            if (self.errnum == 0):
                self.Close()
                pass
            pass
        return
    
    def OnClose(self, event):
        self.Destroy()
        return
