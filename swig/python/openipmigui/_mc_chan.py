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

class ErrDialog(wx.MessageDialog):
    def __init__(self, str):
        wx.MessageDialog.__init__(self, None, str, "Error", wx.OK)
        self.ShowModal()
        return
    pass


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

    def HandleMenu(self, event, eitem, point):
        menu = wx.Menu();
        item = menu.Append(-1, "Set Values")
        menu.Bind(wx.EVT_MENU, self.setvalues, item)
        self.mcchan.tree.PopupMenu(menu, point)
        menu.Destroy()
        return

    def setvalues(self, event):
        print "set values"
        return

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
        item = menu.Append(-1, "User Info")
        menu.Bind(wx.EVT_MENU, self.users, item)
        if (self.medium == OpenIPMI.CHANNEL_MEDIUM_8023_LAN):
            item = menu.Append(-1, "LANPARMS")
            menu.Bind(wx.EVT_MENU, self.lanparms, item)
            item = menu.Append(-1, "Clear LANPARM lock")
            menu.Bind(wx.EVT_MENU, self.clr_lanparm_lock, item)
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
            pass
        elif (self.cb_state == "lanparms"):
            lp = mc.get_lanparm(self.idx)
            lp.get_config(self)
        elif (self.cb_state == "clr_lanparm_lock"):
            lp = mc.get_lanparm(self.idx)
            lp.clear_lock()
            pass
        return

    def lanparm_got_config_cb(self, lanparm, err, lanconfig):
        if (err):
            if (err == OpenIPMI.eagain):
                ErrDialog("LANPARMs are lock, clear the lock if necessary")
            else:
                ErrDialog("Error getting lanparms: "
                          + OpenIPMI.get_error_string(err))
                pass
            return
        _mc_lanparm.MCLanParm(self.mcchan.m, lanparm, lanconfig, self.idx)
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

        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.CenterOnScreen();
        return

    def add_data(self, parent, name, value):
        item = self.tree.AppendItem(parent, name);
        self.tree.SetItemText(item, value, 1)
        return

    def add_info(self, ch, oinfo):
        info = oinfo.info
        item = self.tree.AppendItem(ch, "Info")
        v = [ 0 ]
        rv = info.get_medium(v)
        if (not rv):
            self.add_data(item, "Medium", OpenIPMI.channel_medium_string(v[0]))
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
            self.add_data(item, "Alerting Enabled", str(v[0] != 0))
            pass
        rv = info.get_per_msg_auth(v)
        if (not rv):
            self.add_data(item, "Per Msg Auth", str(v[0] != 0))
            pass
        rv = info.get_user_auth(v)
        if (not rv):
            self.add_data(item, "User Auth", str(v[0] != 0))
            pass
        rv = info.get_access_mode(v)
        if (not rv):
            self.add_data(item, "Access Mode",
                          OpenIPMI.channel_access_mode_string(v[0]))
            pass
        rv = info.get_privilege_limit(v)
        if (not rv):
            self.add_data(item, "Privilege Limit",
                          OpenIPMI.privilege_string(v[0]))
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

        close = wx.Button(self, -1, "Close")
        self.Bind(wx.EVT_BUTTON, self.close, close)
        sizer.Add(close, 0, wx.ALIGN_CENTRE | wx.ALL, 5)

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

        self.tree.Bind(wx.EVT_TREE_ITEM_RIGHT_CLICK, self.TreeMenu)
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
            data.HandleMenu(event, eitem, point)
            pass
        return

    def close(self, event):
        self.Close()
    
    def OnClose(self, event):
        self.Destroy()
