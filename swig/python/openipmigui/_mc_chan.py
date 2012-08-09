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
import gui_popup
import gui_treelist
import _oi_logging
import _mc_lanparm
import _mc_solparm
import _mc_user

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
        if (self.mcchan.info == None):
            return
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
        if (self.mcchan.info == None):
            return
        if (not err):
            self.info = info;
            self.mcchan.info[self.idx]["info"] = self
            v = [ 0 ]
            rv = info.get_medium(v)
            if ((not rv) and (v[0] == OpenIPMI.CHANNEL_MEDIUM_8023_LAN)):
                # Test for SoL with get channel payload support cmd
                rv = mc.send_command(0, 6, 0x4e, [ self.idx ], self)
                if (not rv):
                    return
                pass
            pass
        self.mcchan.done_one()
        return

    def mc_cmd_cb(self, mc, netfn, cmd, rsp):
        if (rsp[0] != 0):
            # Error
            self.mcchan.done_one()
            return
        if (len(rsp) < 9):
            # Eh?  response is too small
            self.mcchan.done_one()
            return
        if (rsp[1] & 0x2):
            # We have SoL support
            self.mcchan.info[self.idx]["SoL"] = True
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
        self.has_sol_set = False
        return

    def HandleMenu(self, event, eitem, point):
        if (self.mcchan.info == None):
            return
        l = [ ("User Info", self.users) ]
        if (self.medium == OpenIPMI.CHANNEL_MEDIUM_8023_LAN):
            l.append( ("LANPARMS", self.lanparms) )
            l.append( ("Clear LANPARM lock", self.clr_lanparm_lock) )
            if ("SoL" in self.mcchan.info[self.idx]):
                l.append( ("SoLPARMS", self.solparms) )
                l.append( ("Clear SoLPARM lock", self.clr_solparm_lock) )
                pass
            pass
        gui_popup.popup(self.mcchan, event, l, point)
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

    def solparms(self, event):
        self.cb_state = "solparms"
        self.mcchan.mc_id.to_mc(self)
        return

    def clr_solparm_lock(self, event):
        self.cb_state = "clr_solparm_lock"
        self.mcchan.mc_id.to_mc(self)
        return

    def mc_cb(self, mc):
        if (self.cb_state == "users"):
            rv = mc.get_users(self.idx, 0, self)
            if (rv):
                self.mcchan.SetError("Could not get users: " +
                                     OpenIPMI.get_error_string(rv))
                pass
            pass
        elif (self.cb_state == "lanparms"):
            lp = mc.get_lanparm(self.idx)
            lp.get_config(self)
        elif (self.cb_state == "clr_lanparm_lock"):
            lp = mc.get_lanparm(self.idx)
            lp.clear_lock()
        elif (self.cb_state == "solparms"):
            sp = mc.get_solparm(self.idx)
            sp.get_config(self)
        elif (self.cb_state == "clr_solparm_lock"):
            sp = mc.get_solparm(self.idx)
            sp.clear_lock()
            pass
        return

    def mc_channel_got_users_cb(self, mc, err, max_users, enabled_users,
                                fixed_users, users):
        if (err):
            self.mcchan.SetError("Error fetching users: " +
                                 OpenIPMI.get_error_string(err))
            return
        if (len(users) == 0):
            self.mcchan.SetError("No users")
            return
        v = [ 0 ]
        users[0].get_channel(v)
        ch = v[0]
        _mc_user.MCUsers(mc, ch, max_users, enabled_users, fixed_users, users)
        return
    
    def lanparm_got_config_cb(self, lanparm, err, lanconfig):
        if (err):
            if (err == OpenIPMI.eagain):
                self.mcchan.SetError(
                    "LANPARMs are locked, clear the lock if necessary")
            else:
                self.mcchan.SetError(
                    "Error getting lanparms: "
                    + OpenIPMI.get_error_string(err))
                pass
            return
        _mc_lanparm.MCLanParm(self.mcchan.m, lanparm, lanconfig, self.idx)
        return
    
    def solparm_got_config_cb(self, solparm, err, solconfig):
        if (err):
            if (err == OpenIPMI.eagain):
                self.mcchan.SetError(
                    "SOLPARMs are locked, clear the lock if necessary")
            else:
                self.mcchan.SetError(
                    "Error getting solparms: "
                    + OpenIPMI.get_error_string(err))
                pass
            return
        _mc_solparm.MCSolParm(self.mcchan.m, solparm, solconfig, self.idx)
        return
    
    pass

class BoolSetter:
    def __init__(self, mcchan, setter):
        self.mcchan = mcchan
        self.setter = setter
        return
    
    def SetItem(self, item):
        self.item = item
        return
    
    def HandleMenu(self, event, eitem, point):
        gui_popup.popup(self.mcchan, event,
                        [ ("Toggle Value", self.togglevalue) ],
                        point)
        return

    def togglevalue(self, event):
        val = str(self.mcchan.GetColumn(self.item, 1))
        if (val == "True") or (val == "true"):
            val = "false"
            bval = 0
        else:
            val = "true"
            bval = 1
            pass
        rv = self.setter(bval)
        if (rv):
            self.mcchan.SetError("Could not toggle value: "
                                 + OpenIPMI.get_error_string(rv))
            return
        self.mcchan.SetColumn(self.item, val, 1);
        return

    pass

class AccessSetter:
    def __init__(self, mcchan, setter):
        self.mcchan = mcchan
        self.setter = setter
        return
    
    def SetItem(self, item):
        self.item = item
        return
    
    def HandleMenu(self, event, eitem, point):
        gui_popup.popup(self.mcchan, event,
                        [ ("Disabled", self.disabled),
                          ("PreBoot", self.preboot),
                          ("Always", self.always),
                          ("Shared", self.shared) ],
                        point)
        return

    def setval(self, val):
        rv = self.setter(val)
        if (rv):
            mcchan.SetError("Could not set value: "
                            + OpenIPMI.get_error_string(rv))
            return
        self.mcchan.SetColumn(self.item, 
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
    def __init__(self, mcchan, setter):
        self.mcchan = mcchan
        self.setter = setter
        return

    def SetItem(self, item):
        self.item = item
        return
    
    def HandleMenu(self, event, eitem, point):
        gui_popup.popup(self.mcchan, event,
                        [ ("Callback", self.callback),
                          ("User", self.user),
                          ("Operator", self.operator),
                          ("Admin", self.admin),
                          ("OEM", self.oem) ],
                        point)
        return

    def setval(self, val):
        rv = self.setter(val)
        if (rv):
            mcchan.SetError("Could not set value: "
                            + OpenIPMI.get_error_string(rv))
            return
        self.mcchanSetColumn(self.item, 
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

class MCChan(gui_treelist.TreeList):
    def __init__(self, m, mc):
        gui_treelist.TreeList.__init__(self, "Channel info for " + m.name,
                                       "Channels",
                                       [ ("Name", 200), ("Value", 400) ] )
        self.m = m;
        self.mc_id = mc.get_id()
        self.count = 0;
        self.info = []
        for i in range(0, OpenIPMI.MAX_USED_CHANNELS) + [14, 15]:
            self.info.append({})
            if (i == 14):
                continue
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
        return

    def add_info(self, ch, oinfo):
        info = oinfo.info
        item = self.Append(ch, "Info", [])
        v = [ 0 ]
        rv = info.get_medium(v)
        if (not rv):
            self.add_data(item, "Medium",
                          [OpenIPMI.channel_medium_string(v[0])])
            pass
        rv = info.get_protocol_type(v)
        if (not rv):
            self.add_data(item, "Protocol Type",
                          [OpenIPMI.channel_protocol_string(v[0])])
            pass
        rv = info.get_session_support(v)
        if (not rv):
            self.add_data(item, "Session Support",
                          [OpenIPMI.channel_session_support_string(v[0])])
            pass
        v = info.get_vendor_id()
        if (v):
            self.add_data(item, "Vendor ID", [v])
            pass
        v = info.get_aux_info()
        if (v):
            self.add_data(item, "Aux Info", [v])
            pass
        return
    
    def add_access(self, ch, oinfo):
        info = oinfo.access
        item = self.Append(ch, "User Access (" + oinfo.tstr + ")", [], oinfo)
        v = [ 0 ]
        rv = info.get_alerting_enabled(v)
        if (not rv):
            mitem = self.add_data(item, "Alerting Enabled", [str(v[0] != 0)],
                                  BoolSetter(self, info.set_alerting_enabled))
            pass
        rv = info.get_per_msg_auth(v)
        if (not rv):
            mitem = self.add_data(item, "Per Msg Auth", [str(v[0] != 0)],
                                  BoolSetter(self, info.set_per_msg_auth))
            pass
        rv = info.get_user_auth(v)
        if (not rv):
            mitem = self.add_data(item, "User Auth", [str(v[0] != 0)],
                                  BoolSetter(self, info.set_user_auth))
            pass
        rv = info.get_access_mode(v)
        if (not rv):
            mitem = self.add_data(item, "Access Mode",
                                  [OpenIPMI.channel_access_mode_string(v[0])],
                                  AccessSetter(self, info.set_access_mode))
            pass
        rv = info.get_privilege_limit(v)
        if (not rv):
            mitem = self.add_data(item, "Privilege Limit",
                                  [OpenIPMI.privilege_string(v[0])],
                                  PrivSetter(self, info.set_privilege_limit))
            pass
        return
    
    def setup(self):
        for i in range(0, OpenIPMI.MAX_USED_CHANNELS) + [15]:
            chi = self.info[i]
            if (len(chi) > 0):
                cdata = MCChanData(self, i)
                ch = self.Append(self.treeroot, str(i), [], cdata)
                if ("info" in chi):
                    info = chi["info"]
                    v = [ 0 ]
                    rv = info.info.get_medium(v)
                    if (not rv):
                        cdata.medium = v[0]
                        s = OpenIPMI.channel_medium_string(v[0])
                        self.SetColumn(ch, s, 1)
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

        self.AfterDone()
        return
        
    def done_one(self):
        self.count -= 1
        if (self.count == 0):
            self.setup()
        return

    def cancel(self):
        self.Close()
        return
    
    def save(self):
        self.mc_id.to_mc(self)
        return

    def mc_cb(self, mc):
        # FIXME - add error handling
        for i in range(0, OpenIPMI.MAX_USED_CHANNELS) + [15]:
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

    def do_on_close(self):
        self.mc_id = None
        self.info = None
        return

    pass
