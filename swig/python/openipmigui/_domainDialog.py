# _domainDialog.py
#
# Prompts for creating a domain in the openipmi GUI
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
import wx
import wx.lib.scrolledpanel as scrolled
import _domain

authtypes = [ 'default', 'none', 'md2', 'md5', 'straight', 'rmcp+' ]
privileges = [ 'default', 'callback', 'user', 'operator', 'admin', 'oem' ]
auth_algs = [ 'default', 'rakp_none', 'rakp_hmac_sha1', 'rakp_hmac_md5' ]
integ_algs = [ 'default', 'none', 'hmac_sha1', 'hmac_md5', 'md5' ]
conf_algs = [ 'default', 'none', 'aes_cbc_128', 'xrc4_128', 'xrc4_40' ]

class ConnInfo(wx.Panel):
    def __init__(self, parent, mainhandler, enable=True):
        if enable:
            sminumval = "0"
        else:
            sminumval = ""
        wx.Panel.__init__(self, parent, size=wx.Size(400, 300))
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.contype = wx.RadioBox(self, -1, "Connection Type",
                                   wx.DefaultPosition, wx.DefaultSize,
                                   [ 'smi', 'lan'], 2, wx.RA_SPECIFY_COLS)
        self.Bind(wx.EVT_RADIOBOX, self.selectType, self.contype);
        self.sizer.Add(self.contype, 0, wx.ALIGN_CENTRE, 2)

        self.smiInfo = wx.Panel(self, -1)
        self.smiInfo_sizer = wx.BoxSizer(wx.VERTICAL)
        box, self.smiNum = self.newField("SMI Number", sminumval,
                                         parent=self.smiInfo)
        self.smiInfo_sizer.Add(box, 0, wx.LEFT | wx.ALL, 2)
        self.sizer.Add(self.smiInfo, 0, wx.ALIGN_CENTRE, 2)
        self.smiInfo.Show(True)

        self.lanInfo = scrolled.ScrolledPanel(self, -1, size=wx.Size(400, 200))
        self.lanInfo_sizer = wx.BoxSizer(wx.VERTICAL)
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        box, self.address = self.newField("Address", parent=self.lanInfo)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        box, self.port = self.newField("Port", "623", parent=self.lanInfo)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.lanInfo_sizer.Add(bbox, 0, wx.LEFT | wx.ALL, 2)
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        box, self.username = self.newField("Username", parent=self.lanInfo)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        box, self.password = self.newField("Password", parent=self.lanInfo,
                                           style=wx.TE_PASSWORD)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.lanInfo_sizer.Add(bbox, 0, wx.LEFT | wx.ALL, 2)

        self.authtype = wx.RadioBox(self.lanInfo, -1, "Authentication Type",
                                   wx.DefaultPosition, wx.DefaultSize,
                                   authtypes, 3, wx.RA_SPECIFY_COLS)
        self.lanInfo_sizer.Add(self.authtype, 0, wx.ALIGN_CENTRE, 2)

        self.privilege = wx.RadioBox(self.lanInfo, -1, "Privilege",
                                     wx.DefaultPosition, wx.DefaultSize,
                                     privileges, 3, wx.RA_SPECIFY_COLS)
        self.lanInfo_sizer.Add(self.privilege, 0, wx.ALIGN_CENTRE, 2)

        self.auth_alg = wx.RadioBox(self.lanInfo, -1,
                                    "Authentication Algorithm",
                                    wx.DefaultPosition, wx.DefaultSize,
                                    auth_algs, 2, wx.RA_SPECIFY_COLS)
        self.lanInfo_sizer.Add(self.auth_alg, 0, wx.ALIGN_CENTRE, 2)

        self.integ_alg = wx.RadioBox(self.lanInfo, -1,
                                     "Integrity Algorithm",
                                     wx.DefaultPosition, wx.DefaultSize,
                                     integ_algs, 3, wx.RA_SPECIFY_COLS)
        self.lanInfo_sizer.Add(self.integ_alg, 0, wx.ALIGN_CENTRE, 2)

        self.conf_alg = wx.RadioBox(self.lanInfo, -1,
                                    "Confidentiality Algorithm",
                                    wx.DefaultPosition, wx.DefaultSize,
                                    conf_algs, 3, wx.RA_SPECIFY_COLS)
        self.lanInfo_sizer.Add(self.conf_alg, 0, wx.ALIGN_CENTRE, 2)

        bbox = wx.BoxSizer(wx.HORIZONTAL)
        box, self.bmc_key = self.newField("BMC Key", parent=self.lanInfo,
                                           style=wx.TE_PASSWORD)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.lookup_uses_priv = wx.CheckBox(self.lanInfo, -1,
                                            "Lookup Uses Privilege")
        bbox.Add(self.lookup_uses_priv, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.lanInfo_sizer.Add(bbox, 0, wx.LEFT | wx.ALL, 2)

        bbox = wx.BoxSizer(wx.HORIZONTAL)
        self.h_intelplus = wx.CheckBox(self.lanInfo, -1,
                                       "Intel Plus Bug")
        self.h_intelplus.SetValue(True)
        bbox.Add(self.h_intelplus, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.h_rakp_wrong_rolem = wx.CheckBox(self.lanInfo, -1,
                                              "RAKP3 Wrong Role(m)")
        bbox.Add(self.h_rakp_wrong_rolem, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.lanInfo_sizer.Add(bbox, 0, wx.LEFT | wx.ALL, 2)

        self.h_rmcpp_integ_sik = wx.CheckBox(self.lanInfo, -1,
                                             "Integrity Uses SIK instead of K(1) ")
        self.lanInfo_sizer.Add(self.h_rmcpp_integ_sik, 0, wx.LEFT | wx.ALL, 2)

        bbox = wx.BoxSizer(wx.HORIZONTAL)
        box, self.address2 = self.newField("Address2", parent=self.lanInfo)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        box, self.port2 = self.newField("Port2", "623", parent=self.lanInfo)
        bbox.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.lanInfo_sizer.Add(bbox, 0, wx.LEFT | wx.ALL, 2)
        
        self.lanInfo.SetSizer(self.lanInfo_sizer)
        self.sizer.Add(self.lanInfo, 0, wx.ALIGN_CENTRE, 2)
        self.lanInfo.SetupScrolling()
        self.lanInfo.Show(False)
        self.SetSizer(self.sizer)

    def newField(self, name, initval="", parent=None, style=0):
        if parent == None:
            parent = self
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(parent, -1, name + ":")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        field = wx.TextCtrl(parent, -1, initval, style=style);
        box.Add(field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        return box, field;

    def selectType(self, event):
        if event.GetInt() == 0:
            self.smiInfo.Show(True)
            self.lanInfo.Show(False)
        else:
            self.smiInfo.Show(False)
            self.lanInfo.Show(True)
        self.Layout()

    def FillinConn(self, con):
        contype = self.contype.GetSelection()
        if (contype == 0):
            con.SetType("smi")
            con.SetPort(str(self.smiNum.GetValue()))
        elif (contype == 1):
            con.SetType("lan")
            con.SetAddress(str(self.address.GetValue()))
            con.SetPort(str(self.port.GetValue()))
            con.SetUsername(str(self.username.GetValue()))
            con.SetPassword(str(self.password.GetValue()))
            con.SetPrivilege(privileges[self.privilege.GetSelection()])
            con.SetAuthtype(authtypes[self.authtype.GetSelection()])
            con.SetAuth_alg(auth_algs[self.auth_alg.GetSelection()])
            con.SetInteg_alg(integ_algs[self.integ_alg.GetSelection()])
            con.SetConf_alg(conf_algs[self.conf_alg.GetSelection()])
            con.SetBmc_key(str(self.bmc_key.GetValue()))
            con.Lookup_uses_priv(self.lookup_uses_priv.GetValue())
            con.SetAddress2(str(self.address2.GetValue()))
            con.SetPort2(str(self.port2.GetValue()))
            if (self.h_intelplus.GetValue()):
                con.AddHack("intelplus")
            if (self.h_rakp_wrong_rolem.GetValue()):
                con.AddHack("rakp3_wrong_rolem")
            if (self.h_rmcpp_integ_sik.GetValue()):
                con.AddHack("rmcpp_intek_sik")

class OpenDomainDialog(wx.Dialog):
    def __init__(self, mainhandler):
        wx.Dialog.__init__(self, None, -1, "Open Domain",
                           size=wx.Size(400, 700),
                           pos=wx.DefaultPosition,
                           style=wx.RESIZE_BORDER)

        self.mainhandler = mainhandler

        self.sizer = wx.BoxSizer(wx.VERTICAL)
        
        box, self.name = self.newField("Domain name")
        self.sizer.Add(box, 0, wx.ALIGN_LEFT | wx.ALL, 2)
        self.name.SetFocus()
        
        bbox = wx.BoxSizer(wx.HORIZONTAL)
        cancel = wx.Button(self, -1, "Cancel")
        self.Bind(wx.EVT_BUTTON, self.cancel, cancel);
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(self, -1, "Ok")
        self.Bind(wx.EVT_BUTTON, self.ok, ok);
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.status = wx.StatusBar(self)
        self.sizer.Add(self.status, 0, wx.ALIGN_LEFT | wx.ALL, 2)

        self.conn = [ ConnInfo(self, mainhandler),
                      ConnInfo(self, mainhandler, False) ]
        self.sizer.Add(self.conn[0], 0, wx.ALIGN_LEFT | wx.ALL, 2)
        self.sizer.Add(self.conn[1], 0, wx.ALIGN_LEFT | wx.ALL, 2)

        self.SetSizer(self.sizer)

        self.Bind(wx.EVT_CLOSE, self.OnClose)
        
    def newField(self, name, initval="", parent=None, style=0):
        if parent == None:
            parent = self
        box = wx.BoxSizer(wx.HORIZONTAL)
        label = wx.StaticText(parent, -1, name + ":")
        box.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        field = wx.TextCtrl(parent, -1, initval, style=style);
        box.Add(field, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
        return box, field;

    def cancel(self, event):
        self.Close(True)


    def ok(self, event):
        name = str(self.name.GetValue())
        if (name == ""):
            self.status.SetStatusText("No name specified")
            return
        d = _domain.Domain(self.mainhandler, name);
        try:
            self.conn[0].FillinConn(d.connection[0])
            self.conn[1].FillinConn(d.connection[1])
            d.Connect()
        except _domain.InvalidDomainInfo, e:
            d.remove()
            self.status.SetStatusText(str(e))
            return
        except Exception, e:
            d.remove()
            self.status.SetStatusText("Unknown error: " + str(e))
            raise e
            return
            
        self.Close(True)

    def OnClose(self, event):
        self.Destroy()

