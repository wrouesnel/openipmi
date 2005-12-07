# _mc.py
#
# openipmi GUI handling for MCs
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
import logging
import _sel

class MCOpHandler:
    def __init__(self, m, func, handler=None, boolval=None):
        self.m = m
        self.func = func
        self.handler = handler
        self.boolval = boolval
        self.item = None

    def SetItem(self, item):
        self.item = item
        return

    def DoOp(self):
        if (self.boolval):
            if (not getattr(self.m, self.boolval)):
                if (self.item):
                    self.m.ui.set_item_text(self.item, None)
                    pass
                return 0
        rv = self.m.mc_id.to_mc(self)
        if (rv == 0):
            rv = self.rv

    def DoUpdate(self):
        if (self.boolval):
            if (not getattr(self.m, self.boolval)):
                if (self.item):
                    self.m.ui.set_item_text(self.item, None)
                    pass
                return
        self.m.mc_id.to_mc(self)
        return

    def mc_cb(self, mc):
        self.rv = getattr(mc, self.func)(self.handler)

class MCRefreshData:
    def __init__(self, m, func):
        self.m = m;
        self.item = None
        self.func = func
        return

    def SetItem(self, item):
        self.item = item
        return

    def DoUpdate(self):
        if (not self.item):
            return
        if (not self.m.mc_id):
            return
        self.m.mc_id.to_mc(self)
        return

    def mc_cb(self, mc):
        val = getattr(mc, self.func)()
        self.m.ui.set_item_text(self.item, str(val))
        return

class MCSelSet:
    def __init__(self, m):
        self.m = m;
        self.refr = MCRefreshData(m, "get_sel_rescan_time")

    def DoUpdate(self):
        self.refr.DoUpdate()

    def SetItem(self, item):
        self.refr.SetItem(item)

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        item = menu.Append(-1, "Modify Value")
        self.m.ui.Bind(wx.EVT_MENU, self.modval, item)
        self.m.ui.PopupMenu(menu, self.m.ui.get_item_pos(eitem))
        menu.Destroy()

    def modval(self, event):
        self.init = True
        self.m.mc_id.to_mc(self)
        dialog = wx.Dialog(None, -1, "Set SEL Rescan Time for " + str(self.m))
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
        self.init = False
        self.m.mc_id.to_mc(self)
        self.dialog.Close()

    def OnClose(self, event):
        self.dialog.Destroy()

    def mc_cb(self, mc):
        if self.init:
            self.sel_rescan_time = mc.get_sel_rescan_time()
        else:
            mc.set_sel_rescan_time(self.ival)
            self.refr.DoUpdate()

        
class MC:
    def __init__(self, d, mc):
        self.d = d
        self.mc_id = mc.get_id()
        self.name = mc.get_name()
        self.cb_state = ""
        d.mcs[self.name] = self
        self.ui = d.ui;
        self.ui.add_mc(self.d, self)
        mc.add_active_handler(self)
        self.has_sel = (mc.sel_device_support() != 0)
        self.event_gen = (mc.ipmb_event_generator_support() != 0)
        self.has_dev_sdrs = (mc.provides_device_sdrs() != 0)
        self.provides_device_sdrs = self.ui.append_item(self,
                                          "Provides Device SDRs",
                                          str(mc.provides_device_sdrs() != 0))
        self.device_available = self.ui.append_item(self, "Device Available",
                                          str(mc.device_available() != 0))
        self.chassis_support = self.ui.append_item(self, "Chassis Support",
                                          str(mc.chassis_support() != 0))
        self.bridge_support = self.ui.append_item(self, "Bridge Support",
                                          str(mc.bridge_support() != 0))
        self.ipmb_event_generator_support = self.ui.append_item(self,
                                   "IPMB Event Generator Support",
                                   str(mc.ipmb_event_generator_support() != 0))
        self.ipmb_event_receiver_support = self.ui.append_item(self,
                                   "IPMB Event Receiver Support",
                                   str(mc.ipmb_event_receiver_support() != 0))
        self.fru_inventory_support = self.ui.append_item(self,
                                   "FRU Inventory Support",
                                   str(mc.fru_inventory_support() != 0))
        self.sel_device_support = self.ui.append_item(self,
                                   "SEL Device Support",
                                   str(mc.sel_device_support() != 0))
        self.sdr_repository_support = self.ui.append_item(self,
                                   "SDR Repository Support",
                                   str(mc.sdr_repository_support() != 0))
        self.sensor_device_support = self.ui.append_item(self,
                                   "Sensor Device Support",
                                   str(mc.sensor_device_support() != 0))
        self.device_id = self.ui.append_item(self, "Device ID",
                                             str(mc.device_id()))
        self.device_revision = self.ui.append_item(self, "Device Revision",
                                                   str(mc.device_revision()))
        self.fw_revision = self.ui.append_item(self, "Firmware Revisions",
                                               str(mc.major_fw_revision())
                                               + "."
                                               + str(mc.minor_fw_revision()))
        self.version = self.ui.append_item(self, "IPMI Version",
                                           str(mc.major_version())
                                           + "."
                                           + str(mc.minor_version()))
        self.manufacturer_id = self.ui.append_item(self,
                                                   "Manufacturer ID",
                                                   str(mc.manufacturer_id()))
        self.product_id = self.ui.append_item(self, "Product ID",
                                              str(mc.product_id()))
        self.aux_fw_revision = self.ui.append_item(self,
                                                   "Aux Firmware Revision",
                                                   mc.aux_fw_revision())
                                               
        self.mguid = self.ui.append_item(self, "GUID", mc.get_guid())

        self.refreshers = [ ]
        self.el_refr = MCOpHandler(self, "get_event_log_enable", self,
                                   "has_sel")
        self.el_item = self.ui.prepend_item(self, "Event Log Enabled",
                                            None, self.el_refr)
        self.refreshers.append(self.el_refr)
        self.ee_refr = self.add_refr_item("Events Enabled",
                                 MCRefreshData(self, "get_events_enable"))
        self.add_refr_item("SEL Rescan Time", MCSelSet(self))

    def __str__(self):
        return self.name
    
    def add_refr_item(self, name, refr):
        item = self.ui.prepend_item(self, name, None, refr)
        refr.SetItem(item)
        self.refreshers.append(refr)
        return refr
        
    def remove(self):
        self.d.mcs.pop(self.name)
        self.ui.remove_mc(self)

    def Changed(self, mc):
        self.has_sel = (mc.sel_device_support() != 0)
        self.event_gen = (mc.ipmb_event_generator_support() != 0)
        self.has_dev_sdrs = (mc.provides_device_sdrs() != 0)
        self.ui.set_item_text(self.provides_device_sdrs,
                              str(mc.provides_device_sdrs() != 0))
        self.ui.set_item_text(self.device_available,
                              str(mc.device_available() != 0))
        self.ui.set_item_text(self.chassis_support,
                              str(mc.chassis_support() != 0))
        self.ui.set_item_text(self.bridge_support,
                              str(mc.bridge_support() != 0))
        self.ui.set_item_text(self.ipmb_event_generator_support,
                                   str(mc.ipmb_event_generator_support() != 0))
        self.ui.set_item_text(self.ipmb_event_receiver_support,
                                   str(mc.ipmb_event_receiver_support() != 0))
        self.ui.set_item_text(self.fru_inventory_support,
                                   str(mc.fru_inventory_support() != 0))
        self.ui.set_item_text(self.sel_device_support,
                                   str(mc.sel_device_support() != 0))
        self.ui.set_item_text(self.sdr_repository_support,
                                   str(mc.sdr_repository_support() != 0))
        self.ui.set_item_text(self.sensor_device_support,
                                   str(mc.sensor_device_support() != 0))
        self.ui.set_item_text(self.device_id, str(mc.device_id()))
        self.ui.set_item_text(self.device_revision,
                              str(mc.device_revision()))
        self.ui.set_item_text(self.fw_revision,
                              str(mc.major_fw_revision())
                              + "."
                              + str(mc.minor_fw_revision()))
        self.ui.set_item_text(self.version,
                              str(mc.major_version())
                              + "."
                              + str(mc.minor_version()))
        self.ui.set_item_text(self.manufacturer_id, str(mc.manufacturer_id()))
        self.ui.set_item_text(self.product_id, str(mc.product_id()))
        self.ui.set_item_text(self.aux_fw_revision, mc.aux_fw_revision())
                                               
        self.ui.set_item_text(self.mguid, mc.get_guid())

    def HandleExpand(self, event):
        for i in self.refreshers:
            i.DoUpdate()

    def HandleMenu(self, event):
        eitem = event.GetItem();
        menu = wx.Menu();
        if self.has_sel:
            item = menu.Append(-1, "Reread SELs")
            self.ui.Bind(wx.EVT_MENU, self.RereadSelsHandler, item)
            item = menu.Append(-1, "Display SELs")
            self.ui.Bind(wx.EVT_MENU, self.DisplaySelsHandler, item)
            item = menu.Append(-1, "Enable Event Log")
            self.ui.Bind(wx.EVT_MENU, self.EnableEventLogHandler, item)
            item = menu.Append(-1, "Disable Event Log")
            self.ui.Bind(wx.EVT_MENU, self.DisableEventLogHandler, item)
            pass
        if self.event_gen:
            item = menu.Append(-1, "Enable Events")
            self.ui.Bind(wx.EVT_MENU, self.EnableEventsHandler, item)
            item = menu.Append(-1, "Disable Events")
            self.ui.Bind(wx.EVT_MENU, self.DisableEventsHandler, item)
            pass
        if self.has_dev_sdrs:
            item = menu.Append(-1, "Refetch SDRs")
            self.ui.Bind(wx.EVT_MENU, self.RefetchSDRsHandler, item)
            pass
        item = menu.Append(-1, "Cold Reset")
        self.ui.Bind(wx.EVT_MENU, self.ColdResetHandler, item)
        item = menu.Append(-1, "Warm Reset")
        self.ui.Bind(wx.EVT_MENU, self.WarmResetHandler, item)
        
        self.ui.PopupMenu(menu, self.ui.get_item_pos(eitem))
        menu.Destroy()

    def RereadSelsHandler(self, event):
        dop = MCOpHandler(self, "reread_sel")
        dop.DoOp()

    def DisplaySelsHandler(self, event):
        _sel.MCSELDisplay(self.mc_id)

    def EnableEventLogHandler(self, event):
        self.cb_state = "enable_event_log"
        self.mc_id.to_mc(self)

    def DisableEventLogHandler(self, event):
        self.cb_state = "disable_event_log"
        self.mc_id.to_mc(self)

    def EnableEventsHandler(self, event):
        self.cb_state = "enable_events"
        self.mc_id.to_mc(self)

    def DisableEventsHandler(self, event):
        self.cb_state = "disable_events"
        self.mc_id.to_mc(self)

    def ColdResetHandler(self, event):
        self.cb_state = "cold_reset"
        self.mc_id.to_mc(self)

    def WarmResetHandler(self, event):
        self.cb_state = "warm_reset"
        self.mc_id.to_mc(self)

    def RefetchSDRsHandler(self, event):
        self.cb_state = "refetch_sdrs"
        self.mc_id.to_mc(self)

    def mc_cb(self, mc):
        if (self.cb_state == "enable_events"):
            mc.set_events_enable(1, self)
        elif (self.cb_state == "disable_events"):
            mc.set_events_enable(0, self)
        if (self.cb_state == "enable_event_log"):
            mc.set_event_log_enable(1, self)
        elif (self.cb_state == "disable_event_log"):
            mc.set_event_log_enable(0, self)
        elif (self.cb_state == "cold_reset"):
            mc.reset(OpenIPMI.MC_RESET_COLD)
        elif (self.cb_state == "warm_reset"):
            mc.reset(OpenIPMI.MC_RESET_WARM)
        elif (self.cb_state == "refetch_sdrs"):
            mc.reread_sensors()
        elif (self.cb_state == "reread_sel"):
            mc.reread_sel()
            pass
        pass

    def mc_events_enable_cb(self, mc, err):
        if (err):
            logging.error("Error setting MC events: " + str(err))
            return
        self.ee_refr.DoUpdate()

    def mc_get_event_log_enable_cb(self, mc, err, val):
        if (err):
            logging.error("Error getting MC event log enable: " + str(err))
            return
        self.ui.set_item_text(el_item, str(val != 0))
        
    def mc_set_event_log_enable_cb(self, mc, err):
        if (err):
            logging.error("Error setting MC event log enable: " + str(err))
            return
        self.el_refr.DoUpdate()

    def mc_active_cb(self, mc, active):
        if (active):
            self.ui.set_item_active(self.treeroot)
        else:
            self.ui.set_item_inactive(self.treeroot)
