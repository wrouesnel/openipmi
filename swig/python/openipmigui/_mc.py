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

class MC:
    def __init__(self, d, mc):
        self.d = d
        self.name = mc.get_name()
        d.mcs[self.name] = self
        self.ui = d.ui;
        self.ui.add_mc(self.d, self)
        mc.add_active_handler(self)
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

    def __str__(self):
        return self.name
    
    def remove(self):
        self.d.mcs.pop(self.name)
        self.ui.remove_mc(self)

    def Changed(self, mc):
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

    def mc_active_cb(self, mc, active):
        if (active):
            self.ui.set_item_active(self.treeroot)
        else:
            self.ui.set_item_inactive(self.treeroot)
