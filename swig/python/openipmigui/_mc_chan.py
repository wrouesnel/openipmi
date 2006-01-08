# _mc_chan.py
#
# openipmi GUI handling for MC channel info
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
import _mc_user

id_st = 500

# Collect all the info for the channels of an MC.  For each channel
# all the info is requested using the types immediately below.  If the
# fetch is a success then it is added to the "info" array of the main
# type.  When all the info is collected, then it is all displayed.
#
# The info array is an array of hashes, one element for each channel.
# Each hash containes one of the following elements: "info" for
# channel info, "n" for non-volatile user access, and "v" for volatile
# user access.

class MCChanUserAcc:
    def __init__(self, mcchan, idx, t):
        self.mcchan = mcchan
        self.idx = idx
        self.t = t
        if (t == "v"):
            self.tstr = "volatile"
        else:
            self.tstr = "nonvolatile"
            pass
        return

    def mc_channel_got_access_cb(self, mc, err, access):
        if (not err):
            self.access = access
            self.mcchan.info[self.idx][self.t] = self
            pass
        self.mcchan.done_one()
        return

    pass

class MCChanInfo:
    def __init__(self, mcchan, idx):
        self.mcchan = mcchan
        self.idx = idx
        return

    def mc_channel_got_info_cb(self, mc, err, info):
        if (not err):
            self.info = info;
            self.mcchan.info[self.idx]["info"] = self
            pass
        self.mcchan.done_one()
        return
    
    pass

class MCChanData:
    def __init__(self, mcchan, idx):
        self.idx = idx;
        self.mcchan = mcchan
        # Assume this unless told otherwise
        self.medium = OpenIPMI.CHANNEL_MEDIUM_IPMB
        return

    def HandleMenu(self, event, eitem, point):
        menu = wx.Menu();
        item = menu.Append(id_st+2, "User Info")
        wx.EVT_MENU(menu, id_st+2, self.users)
        if (self.medium == OpenIPMI.CHANNEL_MEDIUM_8023_LAN):
            item = menu.Append(id_st+3, "LANPARMS")
            wx.EVT_MENU(menu, id_st+3, self.lanparms)
            item = menu.Append(id_st+4, "Clear LANPARM lock")
            wx.EVT_MENU(menu, id_st+4, self.clr_lanparm_lock)
            pass
        self.mcchan.tree.PopupMenu(menu, point)
        menu.Destroy()
        return
    
    def users(self, event):
        self.cb_state = "users"
        self.mcchan.mc_id.to_mc(self)
        return

    def lanparms(self, event):
        self.cb_state = "lanparms"
        self.mcchan.mc_id.to_mc(self)
        return

    def clr_lanparm_lock(self, event):
        self.cb_state = "clr_lanparm_lock"
        self.mcchan.mc_id.to_mc(self)
        return

    def mc_cb(self, mc):
        if (self.cb_state == "users"):
            rv = mc.get_users(self.idx, 0, self)
            if (rv):
                self.mcchan.errstr.SetStatusText("Could not get users: " +
                                                 OpenIPMI.get_error_string(rv),
                                                 0)
                pass
            pass
        elif (self.cb_state == "lanparms"):
            lp = mc.get_lanparm(self.idx)
            lp.get_config(self)
        elif (self.cb_state == "clr_lanparm_lock"):
            lp = mc.get_lanparm(self.idx)
            lp.clear_lock()
            pass
        return

    def mc_channel_got_users_cb(self, mc, err, max_users, enabled_users,
                                fixed_users, users):
        if (err):
            self.mcchan.errstr.SetStatusText("Error fetching users: " +
                                             OpenIPMI.get_error_string(err),
                                             0)
            return
        if (len(users) == 0):
            self.mcchan.errstr.SetStatusText("No users", 0)
            return
        v = [ 0 ]
        users[0].get_channel(v)
        ch = v[0]
        _mc_user.MCUsers(mc, ch, max_users, enabled_users, fixed_users, users)
        return
    
    def lanparm_got_config_cb(self, lanparm, err, lanconfig):
        if (err):
            if (err == OpenIPMI.eagain):
                self.mcchan.errstr.SetStatusText(
                    "LANPARMs are locked, clear the lock if necessary", 0)
            else:
                self.mcchan.errstr.SetStatusText(
                    "Error getting lanparms: "
                    + OpenIPMI.get_error_string(err), 0)
                pass
            return
        _mc_lanparm.MCLanParm(self.mcchan.m, lanparm, lanconfig, self.idx)
        return
    
    pass

class BoolSetter:
    def __init__(self, mcchan, item, setter):
        self.mcchan = mcchan
        self.item = item
        self.setter = setter
        mcchan.tree.SetPyData(item, self)
        return
    
    def HandleMenu(self, event, eitem, point):
        menu = wx.Menu();
        item = menu.Append(id_st+1, "Toggle Value")
        wx.EVT_MENU(menu, id_st+1, self.togglevalue)
        self.mcchan.tree.PopupMenu(menu, point)
        menu.Destroy()
        return

    def togglevalue(self, event):
        val = str(self.mcchan.tree.GetItemText(self.item, 1))
        if (val == "True") or (val == "true"):
            val = "false"
            bval = 0
        else:
            val = "true"
            bval = 1
            pass
        rv = self.setter(bval)
        if (rv):
            mcchan.errstr.SetStatusText("Could not toggle value: "
                                        + OpenIPMI.get_error_string(rv), 0)
            return
        self.mcchan.tree.SetItemText(self.item, val, 1);
        return

    pass

class AccessSetter:
    def __init__(self, mcchan, item, setter):
        self.mcchan = mcchan
        self.item = item
        self.setter = setter
        mcchan.tree.SetPyData(item, self)
        return
    
    def HandleMenu(self, event, eitem, point):
        menu = wx.Menu();
        item = menu.Append(id_st+10, "Disabled")
        wx.EVT_MENU(menu, id_st+10, self.disabled)
        item = menu.Append(id_st+11, "PreBoot")
        wx.EVT_MENU(menu, id_st+11, self.preboot)
        item = menu.Append(id_st+12, "Always")
        wx.EVT_MENU(menu, id_st+12, self.always)
        item = menu.Append(id_st+13, "Shared")
        wx.EVT_MENU(menu, id_st+13, self.shared)
        self.mcchan.tree.PopupMenu(menu, point)
        menu.Destroy()
        return

    def setval(self, val):
        rv = self.setter(val)
        if (rv):
            mcchan.errstr.SetStatusText("Could not set value: "
                                        + OpenIPMI.get_error_string(rv), 0)
            return
        self.mcchan.tree.SetItemText(self.item, 
                                     OpenIPMI.channel_access_mode_string(val),
                                     1)
        return
        
    def disabled(self, event):
        self.setval(OpenIPMI.CHANNEL_ACCESS_MODE_DISABLED)
        return

    def preboot(self, event):
        self.setval(OpenIPMI.CHANNEL_ACCESS_MODE_PRE_BOOT)
        return

    def always(self, event):
        self.setval(OpenIPMI.CHANNEL_ACCESS_MODE_ALWAYS)
        return

    def shared(self, event):
        self.setval(OpenIPMI.CHANNEL_ACCESS_MODE_SHARED)
        return

    pass

class PrivSetter:
    def __init__(self, mcchan, item, setter):
        self.mcchan = mcchan
        self.item = item
        self.setter = setter
        mcchan.tree.SetPyData(item, self)
        return
    
    def HandleMenu(self, event, eitem, point):
        menu = wx.Menu();
        item = menu.Append(id_st+20, "Callback")
        wx.EVT_MENU(menu, id_st+20, self.callback)
        item = menu.Append(id_st+21, "User")
        wx.EVT_MENU(menu, id_st+21, self.user)
        item = menu.Append(id_st+22, "Operator")
        wx.EVT_MENU(menu, id_st+22, self.operator)
        item = menu.Append(id_st+23, "Admin")
        wx.EVT_MENU(menu, id_st+23, self.admin)
        item = menu.Append(id_st+24, "OEM")
        wx.EVT_MENU(menu, id_st+24, self.oem)
        self.mcchan.tree.PopupMenu(menu, point)
        menu.Destroy()
        return

    def setval(self, val):
        rv = self.setter(val)
        if (rv):
            mcchan.errstr.SetStatusText("Could not set value: "
                                        + OpenIPMI.get_error_string(rv), 0)
            return
        self.mcchan.tree.SetItemText(self.item, 
                                     OpenIPMI.privilege_string(val),
                                     1)
        return
        
    def callback(self, event):
        self.setval(OpenIPMI.PRIVILEGE_CALLBACK)
        return

    def user(self, event):
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

class MCChan(wx.Dialog):
    def __init__(self, m, mc):
        wx.Dialog.__init__(self, None, -1, "Channel info for " + m.name,
                           size=wx.Size(500, 600),
                           style=wx.RESIZE_BORDER)
        self.m = m;
        self.mc_id = mc.get_id()
        self.count = 0;
        self.info = []
        for i in range(0, OpenIPMI.MAX_USED_CHANNELS):
            self.info.append({})
            rv = mc.channel_get_info(i, MCChanInfo(self, i))
            if (not rv):
                self.count += 1
                pass
            rv = mc.channel_get_access(i, "volatile",
                                       MCChanUserAcc(self, i, "v"))
            if (not rv):
                self.count += 1
                pass
            rv = mc.channel_get_access(i, "nonvolatile",
                                       MCChanUserAcc(self, i, "n"))
            if (not rv):
                self.count += 1
                pass
            pass

        wx.EVT_CLOSE(self, self.OnClose)
        self.CenterOnScreen();
        return

    def add_data(self, parent, name, value):
        item = self.tree.AppendItem(parent, name);
        self.tree.SetItemText(item, value, 1)
        return item

    def add_info(self, ch, oinfo):
        info = oinfo.info
        item = self.tree.AppendItem(ch, "Info")
        v = [ 0 ]
        rv = info.get_medium(v)
        if (not rv):
            self.add_data(item, "Medium",
                          OpenIPMI.channel_medium_string(v[0]))
            pass
        rv = info.get_protocol_type(v)
        if (not rv):
            self.add_data(item, "Protocol Type",
                          OpenIPMI.channel_protocol_string(v[0]))
            pass
        rv = info.get_session_support(v)
        if (not rv):
            self.add_data(item, "Session Support",
                          OpenIPMI.channel_session_support_string(v[0]))
            pass
        v = info.get_vendor_id()
        if (v):
            self.add_data(item, "Vendor ID", v)
            pass
        v = info.get_aux_info()
        if (v):
            self.add_data(item, "Aux Info", v)
            pass
        return
    
    def add_access(self, ch, oinfo):
        info = oinfo.access
        item = self.tree.AppendItem(ch, "User Access (" + oinfo.tstr + ")")
        self.tree.SetPyData(item, oinfo)
        v = [ 0 ]
        rv = info.get_alerting_enabled(v)
        if (not rv):
            mitem = self.add_data(item, "Alerting Enabled", str(v[0] != 0))
            BoolSetter(self, mitem, info.set_alerting_enabled)
            pass
        rv = info.get_per_msg_auth(v)
        if (not rv):
            mitem = self.add_data(item, "Per Msg Auth", str(v[0] != 0))
            BoolSetter(self, mitem, info.set_per_msg_auth)
            pass
        rv = info.get_user_auth(v)
        if (not rv):
            mitem = self.add_data(item, "User Auth", str(v[0] != 0))
            BoolSetter(self, mitem, info.set_user_auth)
            pass
        rv = info.get_access_mode(v)
        if (not rv):
            mitem = self.add_data(item, "Access Mode",
                                  OpenIPMI.channel_access_mode_string(v[0]))
            AccessSetter(self, mitem, info.set_access_mode)
            pass
        rv = info.get_privilege_limit(v)
        if (not rv):
            mitem = self.add_data(item, "Privilege Limit",
                                  OpenIPMI.privilege_string(v[0]))
            PrivSetter(self, mitem, info.set_privilege_limit)
            pass
        return
    
    def setup(self):
        sizer = wx.BoxSizer(wx.VERTICAL)

        self.tree = gizmos.TreeListCtrl(self)
        self.tree.AddColumn("Name")
        self.tree.AddColumn("Value")
        self.tree.SetMainColumn(0)
        self.tree.SetColumnWidth(0, 300)
        self.tree.SetColumnWidth(1, 400)
        self.treeroot = self.tree.AddRoot("Channels")

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

        for i in range(0, OpenIPMI.MAX_USED_CHANNELS):
            chi = self.info[i]
            if (len(chi) > 0):
                ch = self.tree.AppendItem(self.treeroot, str(i))
                cdata = MCChanData(self, i)
                self.tree.SetPyData(ch, cdata)
                if ("info" in chi):
                    info = chi["info"]
                    v = [ 0 ]
                    rv = info.info.get_medium(v)
                    if (not rv):
                        cdata.medium = v[0]
                        s = OpenIPMI.channel_medium_string(v[0])
                        self.tree.SetItemText(ch, s, 1)
                        pass
                    self.add_info(ch, info)
                    pass
                if ("v" in chi):
                    self.add_access(ch, chi["v"])
                    pass
                if ("n" in chi):
                    self.add_access(ch, chi["n"])
                    pass
                pass
            pass

        wx.EVT_TREE_ITEM_RIGHT_CLICK(self.tree, -1, self.TreeMenu)
        self.tree.Expand(self.treeroot)
        self.SetSizer(sizer)
        self.Show(True)
        return
        
    def done_one(self):
        self.count -= 1
        if (self.count == 0):
            self.setup()
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
        self.Close()
        return
    
    def save(self, event):
        self.mc_id.to_mc(self)
        return

    def mc_cb(self, mc):
        # FIXME - add error handling
        for i in range(0, OpenIPMI.MAX_USED_CHANNELS):
            chi = self.info[i]
            if (len(chi) > 0):
                if ("v" in chi):
                    mc.channel_set_access(chi["v"].access, i, "volatile")
                    pass
                if ("n" in chi):
                    mc.channel_set_access(chi["n"].access, i, "nonvolatile")
                    pass
                pass
            pass
        self.Close()
        return
    
    def OnClose(self, event):
        self.Destroy()
        return
