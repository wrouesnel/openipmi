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
import gui_popup
import gui_treelist
import gui_setdialog
import _oi_logging
import _mc_lanparm

class BoolSetter:
    def __init__(self, mcusers, user, setter):
        self.mcusers = mcusers
        self.setter = setter
        self.user = user
        return
    
    def SetItem(self, item):
        self.item = item
        return
    
    def HandleMenu(self, event, eitem, point):
        gui_popup.popup(self.mcusers, event,
                        [ ("Toggle Value", self.togglevalue) ],
                        point)
        return

    def togglevalue(self, event):
        val = str(self.mcusers.GetColumn(self.item, 1))
        if (val == "True") or (val == "true"):
            val = "false"
            bval = 0
        else:
            val = "true"
            bval = 1
            pass
        rv = self.setter(bval)
        if (rv):
            self.mcusers.SetError("Could not toggle value: "
                                   + OpenIPMI.get_error_string(rv), 0)
            return
        self.user.changed = True
        self.mcusers.SetColumn(self.item, val, 1);
        return

    pass

class IntSetter:
    def __init__(self, mcusers, user, setter, name, currval):
        self.mcusers = mcusers
        self.setter = setter
        self.name = name
        self.currval = currval
        self.user = user
        return
    
    def SetItem(self, item):
        self.item = item
        return
    
    def HandleMenu(self, event, eitem, point):
        gui_popup.popup(self.mcusers, event,
                        [ ("Modify Value", self.modval) ],
                        point)
        return

    def modval(self, event):
        gui_setdialog.SetDialog("Set Value for " + self.name,
                                [ str(self.currval) ],
                                1,
                                self)
        return

    def ok(self, vals):
        val = int(vals[0])
        rv = self.setter(val)
        if (rv):
            return ("Could not set value: "
                    + OpenIPMI.get_error_string(rv))
        self.user.changed = True
        self.mcusers.SetColumn(self.item, str(val), 1)
        self.currval = val
        return

    pass

class StrSetter:
    def __init__(self, mcusers, user, setter, name, currval, prompt):
        self.mcusers = mcusers
        self.setter = setter
        self.name = name
        self.currval = currval
        self.user = user
        self.prompt = prompt
        return
    
    def SetItem(self, item):
        self.item = item
        return
    
    def HandleMenu(self, event, eitem, point):
        gui_popup.popup(self.mcusers, event,
                        [ (self.prompt, self.modval) ],
                        point)
        return

    def modval(self, event):
        gui_setdialog.SetDialog(self.prompt + " for " + self.name,
                                [ str(self.currval) ],
                                1,
                                self)
        return

    def ok(self, vals):
        val = str(vals[0])
        rv = self.setter(val)
        if (rv):
            return ("Could not set value: "
                    + OpenIPMI.get_error_string(rv))
        self.user.changed = True
        self.mcusers.SetColumn(self.item, str(val), 1)
        self.currval = val
        return

    pass

def GetPrivilegeString(val):
    if (val == 15):
        return "NO ACCESS"
    else:
        return OpenIPMI.privilege_string(val)
    return

class PrivSetter:
    def __init__(self, mcusers, user, setter):
        self.mcusers = mcusers
        self.setter = setter
        self.user = user
        return
    
    def SetItem(self, item):
        self.item = item
        return
    
    def HandleMenu(self, event, eitem, point):
        gui_popup.popup(self.mcusers, event,
                        [ ("Callback", self.callback),
                          ("User", self.handleuser),
                          ("Operator", self.operator),
                          ("Admin", self.admin),
                          ("OEM", self.oem),
                          ("NO ACCESS", self.noaccess) ],
                        point)
        return

    def setval(self, val):
        rv = self.setter(val)
        if (rv):
            mcusers.SetError("Could not set value: "
                             + OpenIPMI.get_error_string(rv))
            return
        self.user.changed = True
        self.mcusers.SetColumn(self.item, GetPrivilegeString(val), 1)
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

    def noaccess(self, event):
        self.setval(15)
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

class MCUsers(gui_treelist.TreeList):
    def __init__(self, mc, channel, max_users, enabled_users, fixed_users,
                 users):
        gui_treelist.TreeList.__init__(self, "user info for " + mc.get_name()
                                       + " channel " + str(channel),
                                       "Users",
                                       [ ("Name", 300), ("Value", 400) ] )
        
        self.mc_id = mc.get_id()
        self.count = 0;
        self.users = users
        self.channel = channel
        self.in_save = False

        item = self.add_data(self.treeroot, "Max Users", [ str(max_users) ])
        item = self.add_data(self.treeroot, "Enabled Users",
                           [ str(enabled_users) ])
        item = self.add_data(self.treeroot, "Fixed Users", [str(fixed_users)])
        
        for u in users:
            v = [ 0 ]
            rv = u.get_num(v)
            u.changed = False
            num = v[0]
            if (rv == 0):
                u.num = num
                nm = u.get_name()
                setter = StrSetter(self, u, u.set_password_auto,
                                   "Password", "", "Set Password")
                if (nm):
                    nm = str(nm)
                    us = self.add_data(self.treeroot, str(num), [nm], setter)
                else:
                    us = self.add_data(self.treeroot, str(num), [], setter)
                    nm = ""
                    pass
                setter.SetItem(us)
                if (num > fixed_users):
                    setter = StrSetter(self, u, u.set_name, "Name", nm,
                                       "Modify Value")
                else:
                    setter = None;
                    pass
                item = self.add_data(us, "Name", [nm], setter)

                rv = u.get_enable(v)
                if (rv == 0):
                    s = IntToBoolStr(v[0])
                else:
                    s = "?"
                    pass
                item = self.add_data(us, "Enabled", [s],
                                     BoolSetter(self, u, u.set_enable))

                rv = u.get_link_auth_enabled(v)
                if (rv == 0):
                    s = IntToBoolStr(v[0])
                else:
                    s = "?"
                    pass
                item = self.add_data(us, "Link Auth Enabled", [s],
                                     BoolSetter(self, u,
                                                u.set_link_auth_enabled))

                rv = u.get_msg_auth_enabled(v)
                if (rv == 0):
                    s = IntToBoolStr(v[0])
                else:
                    s = "?"
                    pass
                item = self.add_data(us, "Msg Auth Enabled", [s],
                                     BoolSetter(self, u,
                                                u.set_msg_auth_enabled))

                rv = u.get_access_cb_only(v)
                if (rv == 0):
                    s = IntToBoolStr(v[0])
                else:
                    s = "?"
                    pass
                item = self.add_data(us, "Access Callback Only", [s],
                                     BoolSetter(self, u, u.set_access_cb_only))

                rv = u.get_privilege_limit(v)
                if (rv == 0):
                    s = GetPrivilegeString(v[0])
                else:
                    s = "?"
                    pass
                item = self.add_data(us, "Privilege Limit", [s],
                                     PrivSetter(self, u,
                                                u.set_privilege_limit))

                rv = u.get_session_limit(v)
                if (rv == 0):
                    s = str(v[0])
                else:
                    s = "?"
                    v[0] = 0
                    pass
                item = self.add_data(us, "Session Limit", [s],
                                     IntSetter(self, u, u.set_session_limit,
                                               "Session Limit", v[0]))
                pass
            pass
        
        self.AfterDone()
        return

    def cancel(self):
        if (self.in_save):
            return
        self.Close()
        return
    
    def save(self):
        if (self.in_save):
            return
        self.mc_id.to_mc(self)
        return

    def mc_cb(self, mc):
        self.errnum = 0
        self.waitcount = 0
        self.SetError("")
        for u in self.users:
            if (u.changed):
                rv = mc.set_user(u, self.channel, u.num,
                                 SetUserHandler(self, u.num))
                if (rv):
                    self.SetError("Error setting user "
                                  + str(u.num)  + ": "
                                  + OpenIPMI.get_error_string(rv))
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
            self.SetError("Error setting user " + str(num) + ": "
                          + OpenIPMI.get_error_string(err))
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
    
    def do_on_close(self):
        self.users = None
        return

    pass
