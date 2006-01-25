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
        self.startup = True
        self.sol.open()
        return

    def OnClose(self, event):
        self.sol.force_close()
        self.Destroy();
        return

    def domain_cb(self, domain):
        self.sol = domain.create_sol(self.cnum, self)
        self.dname = domain.get_name()
        return
            
    def HandleOutput(self, data):
        self.sol.write(data)
        return

    def finish_init(self):
        wx.Frame.__init__(self, None, -1,
                          name = ("SoL for " + self.dname + " connection "
                                  + str(self.cnum)))

        menubar = wx.MenuBar()
        filemenu = wx.Menu()
        filemenu.Append(id_st + 1, "Close", "Close")
        wx.EVT_MENU(self, id_st+1, self.close);
        menubar.Append(filemenu, "File")
        self.SetMenuBar(menubar)

        self.term = SolTerm(self, self)
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.sizer.Add(self.term.textctrl, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        self.errstr = wx.StatusBar(self, -1)
        self.sizer.Add(self.errstr, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        self.Show()
        wx.EVT_CLOSE(self, self.OnClose)
        return

    def sol_connection_state_change(self, conn, state, err):
        if (self.startup):
            self.startup = False
            if (err):
                self.ui.ReportError("Connection error for SoL: "
                                    + OpenIPMI.get_error_string(err))
                self.Destroy()
                return
            self.finish_init()
            pass
        self.errstr.SetStatusText("Connection change: " + str(state)
                                  + " " + OpenIPMI.get_error_string(err),
                                  0)
        return

    def close(self, event):
        self.Close()
        return
    
    def sol_data_received(self, conn, string):
        self.term.ProcessInput(string)
        return
    
    def sol_break_detected(self, conn):
        return
    
    def sol_bmc_transmit_overrun(self, conn):
        return

    pass
