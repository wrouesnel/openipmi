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
import gui_popup
import gui_setdialog
import _oi_logging
import _sel
import _mc_chan
import _mc_pefparm

class MCOpHandler:
    def __init__(self, m, func, handler=None, boolval=None):
        self.m = m
        self.func = func
        self.handler = handler
        self.boolval = boolval
        self.item = None
        pass

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
            pass
        rv = self.m.mc_id.to_mc(self)
        if (rv == 0):
            rv = self.rv
            pass
        return

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
        return

    pass

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

    pass

class MCSelSet:
    def __init__(self, m):
        self.m = m;
        self.refr = MCRefreshData(m, "get_sel_rescan_time")
        return

    def DoUpdate(self):
        self.refr.DoUpdate()
        return

    def SetItem(self, item):
        self.refr.SetItem(item)
        return

    def HandleMenu(self, event):
        gui_popup.popup(self.m.ui, event,
                        [ ("Modify Value", self.modval) ])
        return

    def modval(self, event):
        self.init = True
        self.m.mc_id.to_mc(self)

        gui_setdialog.SetDialog("Set SEL Rescan Time for " + str(self.m),
                                [ str(self.sel_rescan_time) ],
                                1,
                                self)
        return

    def ok(self, vals):
        self.ival = int(vals[0])
        self.init = False
        rv = self.m.mc_id.to_mc(self)
        if (rv == 0):
            rv = self.err
            pass
        if (rv != 0):
            return ("Error setting SEL rescan time: "
                    + OpenIPMI.get_error_string(rv))
        return

    def mc_cb(self, mc):
        if self.init:
            self.sel_rescan_time = mc.get_sel_rescan_time()
        else:
            self.err = mc.set_sel_rescan_time(self.ival)
            self.refr.DoUpdate()
            pass
        return

    pass

class PEFLockClearer:
    def __init__(self, mc):
        self.pef = mc.get_pef(self)
        return

    def got_pef_cb(self, pef, err):
        pef.clear_lock();
        return

    pass
        
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

        # Check for PEF capability, send a Get PEF Capabilities cmd
        self.has_pef = False
        mc.send_command(0, 4, 0x10, [ ], self)
        return

    def mc_cmd_cb(self, mc, netfn, cmd, rsp):
        if (rsp[0] != 0):
            # Error
            return
        if (len(rsp) < 4):
            # Response too small
            return
        self.has_pef = True
        return

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
        self.d = None
        self.ui = None
        self.el_refr = None
        self.el_item = None
        self.ee_refr = None
        return

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
        return

    def HandleExpand(self, event):
        for i in self.refreshers:
            i.DoUpdate()
            pass
        return

    def HandleMenu(self, event):
        l = [ ]
        if self.has_sel:
            l.append( ("Reread SELs", self.RereadSelsHandler) )
            l.append( ("Display SELs", self.DisplaySelsHandler) )
            l.append( ("Enable Event Log", self.EnableEventLogHandler) )
            l.append( ("Disable Event Log", self.DisableEventLogHandler) )
            pass
        if self.event_gen:
            l.append( ("Enable Events", self.EnableEventsHandler) )
            l.append( ("Disable Events", self.DisableEventsHandler) )
            pass
        if self.has_dev_sdrs:
            l.append( ("Refetch SDRs", self.RefetchSDRsHandler) )
            pass
        if self.has_pef:
            l.append( ("PEF Parms", self.PEFParms) )
            l.append( ("Clear PEF Lock", self.PEFLockClear) )
            pass
        l.append( ("Cold Reset", self.ColdResetHandler) )
        l.append( ("Warm Reset", self.WarmResetHandler) )
        l.append( ("Channel Info", self.ChannelInfoHandler) )
        gui_popup.popup(self.ui, event, l)
        return

    def RereadSelsHandler(self, event):
        dop = MCOpHandler(self, "reread_sel")
        dop.DoOp()
        return

    def DisplaySelsHandler(self, event):
        _sel.MCSELDisplay(self.mc_id)
        return

    def EnableEventLogHandler(self, event):
        self.cb_state = "enable_event_log"
        self.mc_id.to_mc(self)
        return

    def DisableEventLogHandler(self, event):
        self.cb_state = "disable_event_log"
        self.mc_id.to_mc(self)
        return

    def EnableEventsHandler(self, event):
        self.cb_state = "enable_events"
        self.mc_id.to_mc(self)
        return

    def DisableEventsHandler(self, event):
        self.cb_state = "disable_events"
        self.mc_id.to_mc(self)
        return

    def ColdResetHandler(self, event):
        self.cb_state = "cold_reset"
        self.mc_id.to_mc(self)
        return

    def WarmResetHandler(self, event):
        self.cb_state = "warm_reset"
        self.mc_id.to_mc(self)
        return

    def ChannelInfoHandler(self, event):
        self.cb_state = "channel_info"
        self.mc_id.to_mc(self)
        return

    def RefetchSDRsHandler(self, event):
        self.cb_state = "refetch_sdrs"
        self.mc_id.to_mc(self)
        return

    def PEFParms(self, event):
        self.cb_state = "pef_parms"
        self.mc_id.to_mc(self)
        return

    def PEFLockClear(self, event):
        self.cb_state = "pef_lock_clear"
        self.mc_id.to_mc(self)
        return

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
        elif (self.cb_state == "channel_info"):
            _mc_chan.MCChan(self, mc)
        elif (self.cb_state == "pef_parms"):
            pp = mc.get_pef(self)
            if (pp == None):
                self.ui.ReportError("Unable to allocate PEF config");
                return
        elif (self.cb_state == "pef_lock_clear"):
            PEFLockClearer(mc)
            pass
        return

    def got_pef_cb(self, pef, err):
        if (err):
            self.ui.ReportError("Error fetching PEF: " +
                                OpenIPMI.get_error_string(err))
            return
        rv = pef.get_config(self)
        if (rv):
            self.ui.ReportError("Error starting PEF config fetch: " +
                                OpenIPMI.get_error_string(rv))
            pass
        return

    def pef_got_config_cb(self, pef, err, pefconfig):
        if (err):
            if (err == OpenIPMI.eagain):
                self.ui.ReportError("PEF already locked by another user, "
                                    "Try clearing the lock.")
                pass
            else:
                self.ui.ReportError("Error fetching PEF config: " +
                                    OpenIPMI.get_error_string(err))
                pass
            return
        _mc_pefparm.MCPefParm(self, pef, pefconfig)
        return

    def mc_events_enable_cb(self, mc, err):
        if (err):
            _oi_logging.error("Error setting MC events for "
                              + self.name + ": "
                              + OpenIPMI.get_error_string(err))
            return
        self.ee_refr.DoUpdate()

    def mc_get_event_log_enable_cb(self, mc, err, val):
        if (err):
            _oi_logging.error("Error getting MC event log enable for "
                              + self.name + ": "
                              + OpenIPMI.get_error_string(err))
            return
        self.ui.set_item_text(self.el_item, str(val != 0))
        
    def mc_set_event_log_enable_cb(self, mc, err):
        if (err):
            _oi_logging.error("Error setting MC event log enable for"
                              + self.name + ": "
                              + OpenIPMI.get_error_string(err))
            return
        self.el_refr.DoUpdate()
        return

    def mc_active_cb(self, mc, active):
        if (active):
            self.ui.set_item_active(self.treeroot)
        else:
            self.ui.set_item_inactive(self.treeroot)
            pass
        return

    pass
