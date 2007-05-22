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
import Tix
import gui_setdialog
import gui_term
import gui_errstr

# Note in this file SoL refers to the main SoL object and sol refers
# to the connection.

class AckTimeoutSet:
    def __init__(self, SoL):
        self.SoL = SoL
        gui_setdialog.SetDialog("Set Ack Timeout for SoL",
                                [ self.SoL.sol.get_ACK_timeout() ], 1, self,
                                [ "Value (in microseconds)"] )
        return

    def do_on_close(self):
        self.SoL = None
        return
    
    def ok(self, vals):
        if (self.SoL.sol):
            self.SoL.sol.set_ACK_timeout(int(vals[0]))
        return

    pass


class AckRetriesSet:
    def __init__(self, SoL):
        self.SoL = SoL
        gui_setdialog.SetDialog("Set Ack Retries for SoL",
                                [ self.SoL.sol.get_ACK_retries() ], 1, self,
                                [ "Value (in microseconds)"] )
        return

    def do_on_close(self):
        self.SoL = None
        return
    
    def ok(self, vals):
        if (self.SoL.sol):
            self.SoL.sol.set_ACK_retries(int(vals[0]))
        return

    pass


class SolTerm(gui_term.Terminal):
    def __init__(self, parent, SoL):
        self.SoL = SoL
        gui_term.Terminal.__init__(self, parent)
        return

    def HandleTerminalOutput(self, data):
        self.SoL.HandleOutput(data);
        return

class SoL(Tix.Toplevel):
    def __init__(self, ui, domain_id, cnum):
        Tix.Toplevel.__init__(self)
        self.ui = ui
        self.cnum = cnum;
        self.sol = None
        domain_id.to_domain(self)
        if (self.sol == None):
            return
        self.nack_count = 0
        self.take_input = True
        self.in_destroy = False
        self.title("SoL for " + self.dname + " connection "
                   + str(self.cnum))

        mbar = Tix.Frame(self)
        fileb = Tix.Menubutton(mbar, text="File", underline=0, takefocus=0)
        filemenu = Tix.Menu(fileb, tearoff=0)
        self.filemenu = filemenu
        fileb["menu"] = filemenu
        filemenu.add_command(label="Open", command=self.open)
        filemenu.add_command(label="Close", command=self.close,
                             state="disabled")
        filemenu.add_command(label="Force Close", command=self.forceclose,
                             state="disabled")
        filemenu.add_command(label="Quit", command=self.quit)
        
        ctrlb = Tix.Menubutton(mbar, text="Controls", underline=0, takefocus=0)
        ctrlmenu = Tix.Menu(ctrlb, tearoff=0)
        self.ctrlmenu = ctrlmenu
        ctrlb["menu"] = ctrlmenu

        self.acceptinput = Tix.BooleanVar()
        self.acceptinput.set(True)
        ctrlmenu.add_checkbutton(label="Accept Input",
                                 variable=self.acceptinput,
                                 command=self.AcceptInputToggle)

        self.useenc = Tix.BooleanVar()
        self.useenc.set(self.sol.get_use_encryption())
        ctrlmenu.add_checkbutton(label="Use Encryption",
                                 variable=self.useenc,
                                 command=self.UseEncToggle)

        self.useauth = Tix.BooleanVar()
        self.useauth.set(self.sol.get_use_authentication())
        ctrlmenu.add_checkbutton(label="Use Authentication",
                                 variable=self.useauth,
                                 command=self.UseAuthToggle)

        self.deassert_on_connect = Tix.BooleanVar()
        self.deassert_on_connect.set(
            self.sol.get_deassert_CTS_DCD_DSR_on_connect())
        ctrlmenu.add_checkbutton(label="Deassert CTS/DCD/DSR on connect",
                                 variable=self.deassert_on_connect,
                                 command=self.DeassertOnConnectToggle)

        self.ctsassertable = Tix.BooleanVar()
        self.ctsassertable.set(True)
        ctrlmenu.add_checkbutton(label="CTS Assertable",
                                 variable=self.ctsassertable,
                                 command=self.CTSAssertableToggle,
                                 state="disabled")
        
        self.dcd_dsr = Tix.BooleanVar()
        self.dcd_dsr.set(True)
        ctrlmenu.add_checkbutton(label="DCD/DSR Asserted",
                                 variable=self.dcd_dsr,
                                 command=self.DCDDSRToggle,
                                 state="disabled")
        
        self.ri = Tix.BooleanVar()
        self.ri.set(False)
        ctrlmenu.add_checkbutton(label="RI Asserted",
                                 variable=self.ri,
                                 command=self.RIToggle,
                                 state="disabled")
        
        ctrlmenu.add_command(label="Set Ack Timeout",
                             command=self.SetAckTimeout)
        ctrlmenu.add_command(label="Set Ack Retries",
                             command=self.SetAckRetries)
        ctrlmenu.add_command(label="Send Break",
                             command=self.SendBreak, state="disabled")

        sermenu = Tix.Menu(ctrlmenu, tearoff=0)
        ctrlmenu.add_cascade(label="Serial Rate", menu=sermenu)
        self.servar = Tix.StringVar()
        self.servar.set("default")
        sermenu.add_radiobutton(label="Default", value="default",
                                variable=self.servar, command=self.SetRate)
        sermenu.add_radiobutton(label="9600", value="9600",
                                variable=self.servar, command=self.SetRate)
        sermenu.add_radiobutton(label="19200", value="19200",
                                variable=self.servar, command=self.SetRate)
        sermenu.add_radiobutton(label="38400", value="38400",
                                variable=self.servar, command=self.SetRate)
        sermenu.add_radiobutton(label="57600", value="57600",
                                variable=self.servar, command=self.SetRate)
        sermenu.add_radiobutton(label="115200", value="115200",
                                variable=self.servar, command=self.SetRate)

        serbehavemenu = Tix.Menu(ctrlmenu, tearoff=0)
        ctrlmenu.add_cascade(label="Serial Alert Behavior", menu=serbehavemenu)
        self.serbehave = Tix.StringVar()
        self.serbehave.set("fail")
        serbehavemenu.add_radiobutton(label="Serial Alerts Fail", value="fail",
                                      variable=self.serbehave,
                                      command=self.SetSerialAlerts)
        serbehavemenu.add_radiobutton(label="Serial Alerts Deferred",
                                      value="defer",
                                      variable=self.serbehave,
                                      command=self.SetSerialAlerts)
        serbehavemenu.add_radiobutton(label="Serial Alerts Succeed",
                                      value="succeed",
                                      variable=self.serbehave,
                                      command=self.SetSerialAlerts)

        flushmenu = Tix.Menu(ctrlmenu, tearoff=0)
        self.flushmenu = flushmenu
        ctrlmenu.add_cascade(label="Queue Flush", menu=flushmenu)
        fmenus = [ ]
        flushmenu.add_command(label="Flush BMC Transmit Queue",
                              command=self.FlushBMCXmit,
                              state="disabled")
        fmenus.append("Flush BMC Transmit Queue")
        flushmenu.add_command(label="Flush BMC Receive Queue",
                              command=self.FlushBMCRecv,
                              state="disabled")
        fmenus.append("Flush BMC Receive Queue")
        flushmenu.add_command(label="Flush My Transmit Queue",
                              command=self.FlushMyXmit,
                              state="disabled")
        fmenus.append("Flush My Transmit Queue")
        flushmenu.add_command(label="Flush My Receive Queue",
                              command=self.FlushMyRecv,
                              state="disabled")
        fmenus.append("Flush My Receive Queue")
        flushmenu.add_command(label="Flush BMC Queues",
                              command=self.FlushBMC,
                              state="disabled")
        fmenus.append("Flush BMC Queues")
        flushmenu.add_command(label="Flush My Queues",
                              command=self.FlushMe,
                              state="disabled")
        fmenus.append("Flush My Queues")
        flushmenu.add_command(label="Flush All Queues",
                              command=self.FlushAll,
                              state="disabled")
        fmenus.append("Flush All Queues")
        self.fmenus = fmenus

        mbar.pack(side=Tix.TOP, fill=Tix.X, expand=1)
        fileb.pack(side=Tix.LEFT)
        ctrlb.pack(side=Tix.LEFT)

        self.term = SolTerm(self, self)
        f = Tix.Frame(self)
        f.pack(side=Tix.BOTTOM, fill=Tix.X, expand=1)
        self.errstr = gui_errstr.ErrStr(f)
        self.errstr.pack(side=Tix.LEFT, fill=Tix.X, expand=1)
        self.statestr = gui_errstr.ErrStr(f)
        self.statestr.pack(side=Tix.LEFT, fill=Tix.X, expand=1)

        self.statestr.SetError(OpenIPMI.sol_state_string(
            OpenIPMI.sol_state_closed))
        self.state = OpenIPMI.sol_state_closed

        self.bind("<Destroy>", self.OnDestroy)
        return

    def OnDestroy(self, event):
        self.in_destroy = True
        if (self.sol != None):
            self.sol.force_close()
            self.sol = None
            pass
        return

    def domain_cb(self, domain):
        self.sol = domain.create_sol(self.cnum, self)
        if (self.sol == None):
            self.ui.ReportError("Unable to open SoL connection")
            self.destroy()
            return
        self.dname = domain.get_name()
        return
            
    def HandleOutput(self, data):
        self.sol.write(data)
        return

    def sol_connection_state_change(self, conn, state, err):
        if (self.in_destroy):
            return
        if (err != 0):
            self.errstr.SetError("Connection change: "
                                 + OpenIPMI.sol_state_string(state)
                                 + " " + OpenIPMI.get_error_string(err))
            pass
        self.statestr.SetError(OpenIPMI.sol_state_string(state))
        if ((self.state != OpenIPMI.sol_state_closed)
            and (state == OpenIPMI.sol_state_closed)):
            self.filemenu.entryconfigure("Open", state="normal")
            self.filemenu.entryconfigure("Close", state="disabled")
            self.filemenu.entryconfigure("Force Close", state="disabled")
            self.ctrlmenu.entryconfigure("Use Encryption", state="normal")
            self.ctrlmenu.entryconfigure("Use Authentication", state="normal")
            self.ctrlmenu.entryconfigure("Deassert CTS/DCD/DSR on connect",
                                         state="normal")
            self.ctrlmenu.entryconfigure("CTS Assertable", state="disabled")
            self.ctrlmenu.entryconfigure("DCD/DSR Asserted", state="disabled")
            self.ctrlmenu.entryconfigure("RI Asserted", state="disabled")
            self.ctrlmenu.entryconfigure("Send Break", state="disabled")
            for f in self.fmenus:
                self.flushmenu.entryconfigure(f, state="disabled")
                pass
            pass
        elif ((self.state == OpenIPMI.sol_state_closed)
            and (state != OpenIPMI.sol_state_closed)):
            self.filemenu.entryconfigure("Open", state="disabled")
            self.filemenu.entryconfigure("Close", state="normal")
            self.filemenu.entryconfigure("Force Close", state="normal")
            self.ctrlmenu.entryconfigure("Use Encryption", state="disabled")
            self.ctrlmenu.entryconfigure("Use Authentication",
                                         state="disabled")
            self.ctrlmenu.entryconfigure("Deassert CTS/DCD/DSR on connect",
                                         state="disabled")
            self.ctrlmenu.entryconfigure("CTS Assertable", state="normal")
            self.ctrlmenu.entryconfigure("DCD/DSR Asserted", state="normal")
            self.ctrlmenu.entryconfigure("RI Asserted", state="normal")
            self.ctrlmenu.entryconfigure("Send Break", state="normal")
            for f in self.fmenus:
                self.flushmenu.entryconfigure(f, state="normal")
                pass
            pass
        self.state = state
        return

    def open(self):
        self.sol.open()
        return
    
    def close(self):
        self.sol.close()
        return
    
    def forceclose(self):
        self.sol.force_close()
        return
    
    def quit(self):
        self.destroy()
        return

    def AcceptInputToggle(self):
        if (self.acceptinput.get()):
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

    def UseEncToggle(self):
        self.sol.set_use_encryption(self.useenc.get())
        return
    
    def UseAuthToggle(self):
        self.sol.set_use_authentication(self.useauth.get())
        return
    
    def DeassertOnConnectToggle(self):
        self.sol.set_deassert_CTS_DCD_DSR_on_connect(
            self.deassert_on_connect.get())
        return
    
    def CTSAssertableToggle(self):
        self.sol.set_CTS_assertable(self.ctsassertable.get())
        return
    
    def DCDDSRToggle(self):
        self.sol.set_DCD_DSR_asserted(self.dcd_dsr.get())
        return
    
    def RIToggle(self):
        self.sol.set_RI_asserted(self.ri.get())
        return
    
    def SetAckTimeout(self):
        AckTimeoutSet(self)
        return

    def SetAckRetries(self):
        AckRetriesSet(self)
        return

    def SetRate(self):
        val = self.servar.get()
        if (val == "default"):
            self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_DEFAULT)
        elif (val == "9600"):
            self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_9600)
        elif (val == "19200"):
            self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_19200)
        elif (val == "38400"):
            self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_38400)
        elif (val == "57600"):
            self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_57600)
        elif (val == "115200"):
            self.sol.set_bit_rate(OpenIPMI.SOL_BIT_RATE_115200)
            pass
        return

    def SetSerialAlerts(self):
        val = self.serbehave.get()
        if (val == "fail"):
            self.sol.set_shared_serial_alert_behavior(
                OpenIPMI.sol_serial_alerts_fail)
        elif (val == "deferred"):
            self.sol.set_shared_serial_alert_behavior(
                OpenIPMI.sol_serial_alerts_deferred)
        elif (val == "succeed"):
            self.sol.set_shared_serial_alert_behavior(
                OpenIPMI.sol_serial_alerts_succeed)
        return

    def FlushBMCXmit(self):
        self.sol.flush(OpenIPMI.SOL_BMC_TRANSMIT_QUEUE)
        return

    def FlushBMCRecv(self):
        self.sol.flush(OpenIPMI.SOL_BMC_RECEIVE_QUEUE)
        return

    def FlushMyXmit(self):
        self.sol.flush(OpenIPMI.SOL_MANAGEMENT_CONSOLE_TRANSMIT_QUEUE)
        return

    def FlushMyRecv(self):
        self.sol.flush(OpenIPMI.SOL_MANAGEMENT_CONSOLE_RECEIVE_QUEUE)
        return

    def FlushBMC(self):
        self.sol.flush(OpenIPMI.SOL_BMC_QUEUES)
        return

    def FlushMe(self):
        self.sol.flush(OpenIPMI.SOL_MANAGEMENT_CONSOLE_QUEUES)
        return

    def FlushAll(self):
        self.sol.flush(OpenIPMI.SOL_ALL_QUEUES)
        return

    def SendBreak(self):
        self.sol.send_break()
        return

    def sol_data_received(self, conn, string):
        if (not self.take_input):
            self.nack_count += 1
            return 1
        try:
            self.term.ProcessInput(string)
        except Exception, e:
            import sys
            t, v, b = sys.exc_info()
            sys.excepthook(t, v, b)
            del b
            pass
        return 0
    
    def sol_break_detected(self, conn):
        self.errstr.SetError("Received break")
        return
    
    def sol_bmc_transmit_overrun(self, conn):
        self.errstr.SetError("BMC Transmit Overrun")
        return

    pass
