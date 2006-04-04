# _SoL.py
#
# openipmi GUI SoL handling
#
# Author: MontaVista Software, Inc.
#         Corey Minyard <minyard@mvista.com>
#         source@mvista.com
#
# Copyright 2006 MontaVista Software Inc.
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
import _term
import gui_errstr

id_st = 1100

# Note in this file SoL refers to the main SoL object and sol refers
# to the connection.

class SolTerm(_term.Terminal):
    def __init__(self, parent, SoL):
        self.SoL = SoL
        _term.Terminal.__init__(self, parent)
        return

    def HandleTerminalOutput(self, data):
        self.SoL.HandleOutput(data);
        return

class SoL(wx.Frame):
    def __init__(self, ui, domain_id, cnum):
        self.ui = ui
        self.cnum = cnum;
        self.sol = None
        domain_id.to_domain(self)
        if (self.sol == None):
            return
        self.nack_count = 0
        self.take_input = True

        wx.Frame.__init__(self, None, -1,
                          "SoL for " + self.dname + " connection "
                          + str(self.cnum),
                          name = ("SoL for " + self.dname + " connection "
                                  + str(self.cnum)))

        menubar = wx.MenuBar()
        filemenu = wx.Menu()
        self.openmenu = wx.MenuItem(filemenu, id_st + 1, "Open", "Open")
        filemenu.AppendItem(self.openmenu)
        wx.EVT_MENU(self, id_st+1, self.open);
        self.closemenu = wx.MenuItem(filemenu, id_st + 2, "Close", "Close")
        filemenu.AppendItem(self.closemenu)
        self.closemenu.Enable(False)
        wx.EVT_MENU(self, id_st+2, self.close);
        self.forceclosemenu = wx.MenuItem(filemenu, id_st + 3, "Force Close",
                                          "Force Close")
        filemenu.AppendItem(self.forceclosemenu)
        self.forceclosemenu.Enable(False)
        wx.EVT_MENU(self, id_st+3, self.forceclose);
        self.quitmenu = wx.MenuItem(filemenu, id_st + 4, "Quit", "Quit")
        filemenu.AppendItem(self.quitmenu)
        wx.EVT_MENU(self, id_st+4, self.quit);
        menubar.Append(filemenu, "File")
        
        controlmenu = wx.Menu()
        self.acceptinputmenu = wx.MenuItem(controlmenu, id_st + 10,
                                           "Accept Input",  "Accept Input")
        controlmenu.AppendItem(self.acceptinputmenu)
        self.acceptinputmenu.Check(True)
        wx.EVT_MENU(self, id_st+10, self.AcceptInputToggle);
        self.useencmenu = wx.MenuItem(controlmenu, id_st + 11,
                                      "Use Encryption", "Use Encryption")
        controlmenu.AppendItem(self.useencmenu)
        self.useencmenu.Check(self.sol.get_use_encryption())
        wx.EVT_MENU(self, id_st+11, self.UseEncToggle);
        self.useauthmenu = wx.MenuItem(controlmenu, id_st + 12,
                                       "Use Authentication",
                                       "Use Authentication")
        controlmenu.AppendItem(self.useauthmenu)
        self.useauthmenu.Check(self.sol.get_use_authentication())
        wx.EVT_MENU(self, id_st+12, self.UseAuthToggle);
        self.deassert_on_connect_menu = wx.MenuItem(
            controlmenu, id_st + 13,
            "Deassert CTS/DCD/DSR on connect",
            "Deassert CTS/DCD/DSR on connect")
        controlmenu.AppendItem(self.deassert_on_connect_menu)
        self.deassert_on_connect_menu.Check(
            self.sol.get_deassert_CTS_DCD_DSR_on_connect())
        wx.EVT_MENU(self, id_st+13, self.DeassertOnConnectToggle);
        self.ctsassertablemenu = wx.MenuItem(controlmenu, id_st + 14,
                                             "CTS Assertable",
                                             "CTS Assertable")
        controlmenu.AppendItem(self.ctsassertablemenu)
        self.ctsassertablemenu.Check(True)
        self.ctsassertablemenu.Enable(False)
        wx.EVT_MENU(self, id_st+14, self.CTSAssertableToggle);
        self.dcd_dsr_menu = wx.MenuItem(controlmenu, id_st + 15,
                                        "DCD/DSR Asserted", "DCD/DSR Asserted")
        controlmenu.AppendItem(self.dcd_dsr_menu)
        self.dcd_dsr_menu.Check(True)
        self.dcd_dsr_menu.Enable(False)
        wx.EVT_MENU(self, id_st+15, self.DCDDSRToggle);
        self.ri_menu = wx.MenuItem(controlmenu, id_st + 16,
                                   "RI Asserted", "RI Asserted")
        controlmenu.AppendItem(self.ri_menu)
        self.ri_menu.Check(False)
        self.ri_menu.Enable(False)
        wx.EVT_MENU(self, id_st+16, self.RIToggle);
        controlmenu.Append(id_st+17, "Set Ack Timeout", "Set Ack Timeout")
        wx.EVT_MENU(self, id_st+17, self.SetAckTimeout);
        controlmenu.Append(id_st+18, "Set Ack Retries", "Set Ack Retries")
        wx.EVT_MENU(self, id_st+18, self.SetAckRetries);
        self.breakmenu = wx.MenuItem(controlmenu, id_st+19,
                                     "Send Break", "Send Break")
        controlmenu.AppendItem(self.breakmenu)
        self.breakmenu.Enable(False)
        wx.EVT_MENU(self, id_st+19, self.SendBreak);
        
        smenu = wx.Menu()
        smenu.AppendRadioItem(id_st+20, "Default", "Default")
        wx.EVT_MENU(self, id_st+20, self.ratedefault)
        smenu.AppendRadioItem(id_st+21, "9600", "9600")
        wx.EVT_MENU(self, id_st+21, self.rate9600)
        smenu.AppendRadioItem(id_st+22, "19200", "19200")
        wx.EVT_MENU(self, id_st+22, self.rate19200)
        smenu.AppendRadioItem(id_st+23, "38400", "38400")
        wx.EVT_MENU(self, id_st+23, self.rate38400)
        smenu.AppendRadioItem(id_st+24, "57600", "57600")
        wx.EVT_MENU(self, id_st+24, self.rate57600)
        smenu.AppendRadioItem(id_st+25, "115200", "115200")
        wx.EVT_MENU(self, id_st+25, self.rate115200)
        controlmenu.AppendMenu(-1, "Serial Rate", smenu,
                               "Set serial speed")

        smenu = wx.Menu()
        beh = self.sol.get_shared_serial_alert_behavior()
        mi = wx.MenuItem(smenu, id_st+30, "Serial Alerts Fail",
                         "Serial Alerts Fail", kind=wx.ITEM_RADIO)
        smenu.AppendItem(mi)
        wx.EVT_MENU(self, id_st+30, self.SerialAlertsFail)
        if (beh == OpenIPMI.sol_serial_alerts_fail):
            mi.Check(True)
        mi = wx.MenuItem(smenu, id_st+31, "Serial Alerts Deferred",
                         "Serial Alerts Deferred", kind=wx.ITEM_RADIO)
        smenu.AppendItem(mi)
        wx.EVT_MENU(self, id_st+31, self.SerialAlertsDeferred)
        if (beh == OpenIPMI.sol_serial_alerts_deferred):
            mi.Check(True)
        mi = wx.MenuItem(smenu, id_st+32, "Serial Alerts Succeed",
                         "Serial Alerts Succeed", kind=wx.ITEM_RADIO)
        smenu.AppendItem(mi)
        wx.EVT_MENU(self, id_st+32, self.SerialAlertsSucceed)
        if (beh == OpenIPMI.sol_serial_alerts_succeed):
            mi.Check(True)
        controlmenu.AppendMenu(-1, "Serial Alert Behavior", smenu,
                               "Set Serial Alert Behavior")

        smenu = wx.Menu()
        fmenus = [ ]
        mi = wx.MenuItem(smenu, id_st+40, "Flush BMC Transmit Queue",
                         "Flush BMC Transmit Queue")
        smenu.AppendItem(mi)
        fmenus.append(mi)
        wx.EVT_MENU(self, id_st+40, self.FlushBMCXmit)
        mi = wx.MenuItem(smenu, id_st+41, "Flush BMC Receive Queue",
                         "Flush BMC Receive Queue")
        smenu.AppendItem(mi)
        fmenus.append(mi)
        wx.EVT_MENU(self, id_st+41, self.FlushBMCRecv)
        mi = wx.MenuItem(smenu, id_st+42, "Flush My Transmit Queue",
                         "Flush My Transmit Queue")
        smenu.AppendItem(mi)
        fmenus.append(mi)
        wx.EVT_MENU(self, id_st+42, self.FlushMyXmit)
        mi = wx.MenuItem(smenu, id_st+43, "Flush My Receive Queue",
                         "Flush My Receive Queue")
        smenu.AppendItem(mi)
        fmenus.append(mi)
        wx.EVT_MENU(self, id_st+43, self.FlushMyRecv)
        mi = wx.MenuItem(smenu, id_st+44, "Flush BMC Queues", "Flush BMC Queues")
        smenu.AppendItem(mi)
        fmenus.append(mi)
        wx.EVT_MENU(self, id_st+44, self.FlushBMC)
        mi = wx.MenuItem(smenu, id_st+45, "Flush My Queues", "Flush My Queues")
        smenu.AppendItem(mi)
        fmenus.append(mi)
        wx.EVT_MENU(self, id_st+45, self.FlushMe)
        mi = wx.MenuItem(smenu, id_st+46, "Flush All Queues", "Flush Al Queues")
        smenu.AppendItem(mi)
        fmenus.append(mi)
        wx.EVT_MENU(self, id_st+46, self.FlushAll)
        controlmenu.AppendMenu(-1, "Queue Flush", smenu,
                               "Queue Flush")
        for f in fmenus:
            f.Enable(False)
            pass
        self.fmenus = fmenus

        menubar.Append(controlmenu, "Controls")
        self.SetMenuBar(menubar)

        self.term = SolTerm(self, self)
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.term.textctrl, 1,
                       wx.ALIGN_CENTRE | wx.ALL | wx.GROW, 2)
        hsizer = wx.BoxSizer(wx.HORIZONTAL)
        self.sizer.Add(hsizer, 0, wx.ALIGN_CENTRE | wx.ALL | wx.GROW, 2)
        self.errstr = gui_errstr.ErrStr(self)
        hsizer.Add(self.errstr, 4, wx.ALIGN_CENTRE | wx.ALL | wx.GROW, 2)
        self.statestr = gui_errstr.ErrStr(self)
        hsizer.Add(self.statestr, 1, wx.ALIGN_CENTRE | wx.ALL, 2)
        self.SetSizer(self.sizer)


        self.statestr.SetError(OpenIPMI.sol_state_string(
            OpenIPMI.sol_state_closed))
        self.state = OpenIPMI.sol_state_closed
        self.Show()
        wx.EVT_CLOSE(self, self.OnClose)
        return

    def OnClose(self, event):
        self.sol.force_close()
        self.Destroy();
        return

    def domain_cb(self, domain):
        self.sol = domain.create_sol(self.cnum, self)
        if (self.sol == None):
            self.ui.ReportError("Unable to open SoL connection")
            return
        self.dname = domain.get_name()
        return
            
    def HandleOutput(self, data):
        self.sol.write(data)
        return

        return

    def sol_connection_state_change(self, conn, state, err):
        if (err != 0):
            self.errstr.SetError("Connection change: "
                                 + OpenIPMI.sol_state_string(state)
                                 + " " + OpenIPMI.get_error_string(err))
            pass
        self.statestr.SetError(OpenIPMI.sol_state_string(state))
        if ((self.state != OpenIPMI.sol_state_closed)
            and (state == OpenIPMI.sol_state_closed)):
            self.openmenu.Enable(True)
            self.closemenu.Enable(False)
            self.forceclosemenu.Enable(False)
            self.useencmenu.Enable(True)
            self.useauthmenu.Enable(True)
            self.deassert_on_connect_menu.Enable(True)
            self.ctsassertablemenu.Enable(False)
            self.dcd_dsr_menu.Enable(False)
            self.ri_menu.Enable(False)
            self.breakmenu.Enable(False)
            for f in self.fmenus:
                f.Enable(False)
                pass
            pass
        elif ((self.state == OpenIPMI.sol_state_closed)
            and (state != OpenIPMI.sol_state_closed)):
            self.openmenu.Enable(False)
            self.closemenu.Enable(True)
            self.forceclosemenu.Enable(True)
            self.useencmenu.Enable(False)
            self.useauthmenu.Enable(False)
            self.deassert_on_connect_menu.Enable(False)
            self.ctsassertablemenu.Enable(True)
            self.dcd_dsr_menu.Enable(True)
            self.ri_menu.Enable(True)
            self.breakmenu.Enable(True)
            for f in self.fmenus:
                f.Enable(True)
                pass
            pass
        self.state = state
        return

    def open(self, event):
        self.sol.open()
        return
    
    def close(self, event):
        self.sol.close()
        return
    
    def forceclose(self, event):
        self.sol.force_close()
        return
    
    def quit(self, event):
        self.Close()
        return

    def AcceptInputToggle(self, event):
        if (event.IsChecked()):
            self.take_input = True
            for i in range(0, self.nack_count):
                self.sol.release_nack();
                pass
            self.nack_count = 0;
            pass
        else:
            self.take_input = False
            pass
        return

    def UseEncToggle(self, event):
        if (event.IsChecked()):
            self.sol.set_use_encryption(1)
        else:
            self.sol.set_use_encryption(0)
        return
    
    def UseAuthToggle(self, event):
        if (event.IsChecked()):
            self.sol.set_use_authentication(1)
        else:
            self.sol.set_use_authentication(0)
        return
    
    def DeassertOnConnectToggle(self, event):
        if (event.IsChecked()):
            self.sol.set_deassert_CTS_DCD_DSR_on_connect(1)
        else:
            self.sol.set_deassert_CTS_DCD_DSR_on_connect(0)
        return
    
    def CTSAssertableToggle(self, event):
        if (event.IsChecked()):
            self.sol.set_CTS_assertable(1)
        else:
            self.sol.set_CTS_assertable(0)
        return
    
    def DCDDSRToggle(self, event):
        if (event.IsChecked()):
            self.sol.set_DCD_DSR_asserted(1)
        else:
            self.sol.set_DCD_DSR_asserted(0)
        return
    
    def RIToggle(self, event):
        if (event.IsChecked()):
            self.sol.set_RI_asserted(1)
        else:
            self.sol.set_RI_asserted(0)
        return
    
    def SetAckTimeout(self, event):
        while (True):
            dialog = wx.TextEntryDialog(self, "Ack Timeout",
                                        "Specify the timeout in microseconds",
                                        str(self.sol.get_ACK_timeout()),
                                        wx.OK | wx.CANCEL)
            if (dialog.ShowModal() == wx.ID_OK):
                try:
                    val = int(dialog.GetValue())
                except:
                    pass
                else:
                    self.sol.set_ACK_timeout(val)
                    return
                pass
            else:
                return
            pass
        return

    def SetAckRetries(self, event):
        while (True):
            dialog = wx.TextEntryDialog(
                self, "Ack Retries",
                "Specify the number of retries before failure",
                str(self.sol.get_ACK_retries()),
                wx.OK | wx.CANCEL)
            if (dialog.ShowModal() == wx.ID_OK):
                try:
                    val = int(dialog.GetValue())
                except:
                    pass
                else:
                    self.sol.set_ACK_retries(val)
                    return
                pass
            else:
                return
            pass
        return

    def ratedefault(self, event):
        self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_DEFAULT)
        return

    def rate9600(self, event):
        self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_9600)
        return

    def rate19200(self, event):
        self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_19200)
        return

    def rate38400(self, event):
        self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_38400)
        return

    def rate57600(self, event):
        self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_57600)
        return

    def rate115200(self, event):
        self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_115200)
        return

    def SerialAlertsFail(self, event):
        self.sol.set_shared_serial_alert_behavior(
            OpenIPMI.sol_serial_alerts_fail)
        return

    def SerialAlertsDeferred(self, event):
        self.sol.set_shared_serial_alert_behavior(
            OpenIPMI.sol_serial_alerts_deferred)
        return

    def SerialAlertsSucceed(self, event):
        self.sol.set_shared_serial_alert_behavior(
            OpenIPMI.sol_serial_alerts_succeed)
        return

    def FlushBMCXmit(self, event):
        self.sol.flush(OpenIPMI.SOL_BMC_TRANSMIT_QUEUE)
        return

    def FlushBMCRecv(self, event):
        self.sol.flush(OpenIPMI.SOL_BMC_RECEIVE_QUEUE)
        return

    def FlushMyXmit(self, event):
        self.sol.flush(OpenIPMI.SOL_MANAGEMENT_CONSOLE_TRANSMIT_QUEUE)
        return

    def FlushMyRecv(self, event):
        self.sol.flush(OpenIPMI.SOL_MANAGEMENT_CONSOLE_RECEIVE_QUEUE)
        return

    def FlushBMC(self, event):
        self.sol.flush(OpenIPMI.SOL_BMC_QUEUES)
        return

    def FlushMe(self, event):
        self.sol.flush(OpenIPMI.SOL_MANAGEMENT_CONSOLE_QUEUES)
        return

    def FlushAll(self, event):
        self.sol.flush(OpenIPMI.SOL_ALL_QUEUES)
        return

    def SendBreak(self, event):
        self.sol.send_break()
        return

    def sol_data_received(self, conn, string):
        if (not self.take_input):
            self.nack_count += 1
            return 1
        self.term.ProcessInput(string)
        return 0
    
    def sol_break_detected(self, conn):
        self.errstr.SetError("Received break")
        return
    
    def sol_bmc_transmit_overrun(self, conn):
        self.errstr.SetError("BMC Transmit Overrun")
        return

    pass
