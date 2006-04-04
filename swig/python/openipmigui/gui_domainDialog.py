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
import OpenIPMI
import _domain
import gui_errstr

authtypes = [ 'default', 'none', 'md2', 'md5', 'straight', 'rmcp+' ]
privileges = [ 'default', 'callback', 'user', 'operator', 'admin', 'oem' ]
auth_algs = [ 'default', 'rakp_none', 'rakp_hmac_sha1', 'rakp_hmac_md5' ]
integ_algs = [ 'default', 'none', 'hmac_sha1', 'hmac_md5', 'md5' ]
conf_algs = [ 'default', 'none', 'aes_cbc_128', 'xrc4_128', 'xrc4_40' ]

class ConnTypeInfo(scrolled.ScrolledPanel):
    def __init__(self, contype, parent):
        scrolled.ScrolledPanel.__init__(self, parent, -1,
                                        size=wx.Size(400, 200))
        self.contype = contype
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        self.fields = [ ]

        args = OpenIPMI.alloc_empty_args(str(contype))
        self.args = args

        self.errstr = gui_errstr.ErrStr(self)
        self.sizer.Add(self.errstr, 0, wx.ALIGN_CENTRE | wx.ALL | wx.GROW, 2)

        i = 0
        rv = 0
        box = None
        while (rv == 0):
            name = [ "" ]
            vtype = [ "" ]
            vrange = [ "" ]
            vhelp = [ "" ]
            value = [ "" ]
            rv = args.get_val(i, name, vtype, vhelp, value, vrange)
            if (rv == 0):
                if (vhelp[0][0] == '*'):
                    optional = False
                    vhelp[0] = vhelp[0][1:]
                else:
                    optional = True
                    pass
                if (vhelp[0][0] == '!'):
                    password = True
                    vhelp[0] = vhelp[0][1:]
                else:
                    password = False
                    pass
                
                do_box = True
                if (vtype[0] == "bool"):
                    fw = wx.CheckBox(self, -1, name[0])
                    if ((value[0] != None) and (value[0] == "true")):
                        fw.SetValue(1)
                        pass
                    sw = fw
                    pass
                elif (vtype[0] == "enum"):
                    do_box = False
                    fw = wx.RadioBox(self, -1, name[0],
                                     wx.DefaultPosition, wx.DefaultSize,
                                     vrange, 2, wx.RA_SPECIFY_COLS)
                    if (value[0] != None):
                        fw.SetStringSelection(value[0])
                        pass
                    sw = fw
                    pass
                elif (vtype[0] == "str"):
                    bbox = wx.BoxSizer(wx.HORIZONTAL)
                    label = wx.StaticText(self, -1, name[0] + ":")
                    bbox.Add(label, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
                    if (value[0] == None):
                        value[0] = ""
                        pass
                    style = 0
                    if (password):
                        style = wx.TE_PASSWORD
                    fw = wx.TextCtrl(self, -1, value[0], style=style);
                    bbox.Add(fw, 0, wx.ALIGN_CENTRE | wx.ALL, 5)
                    sw = bbox
                    pass
                else:
                    continue

                if (do_box):
                    if (box == None):
                        box = wx.BoxSizer(wx.HORIZONTAL)
                        self.sizer.Add(box, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
                        done = False
                        pass
                    else:
                        done = True;
                        pass
                    box.Add(sw, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
                    if (done):
                        box = None
                    pass
                else:
                    self.sizer.Add(sw, 0, wx.ALIGN_CENTRE | wx.ALL, 2)
                    box = None;
                    pass
                self.fields.append( (i, name[0], vtype[0], fw) )
                pass
            i += 1
            pass
        self.SetupScrolling()
        self.SetSizer(self.sizer)
        return

    def SetupArgs(self):
        self.errstr.SetError("")
        args = self.args
        for f in self.fields:
            idx = f[0]
            vtype = f[2]
            fw = f[3]
            if (vtype == "bool"):
                if (fw.IsChecked()):
                    val = "true"
                else:
                    val = "false"
                    pass
                pass
            elif (vtype == "enum"):
                val = str(fw.GetStringSelection())
                pass
            elif (vtype == "str"):
                val = str(fw.GetValue())
                if (val == ""):
                    val = None
                    pass
                pass
            else:
                continue
            rv = args.set_val(idx, None, val);
            if (rv != 0):
                self.errstr.SetError("Error setting field " + f[1] + ": "
                                     + OpenIPMI.get_error_string(rv))
                raise Exception()
            pass
        return args
    pass

class ConnInfo(wx.Panel):
    def __init__(self, parent, mainhandler, enable=True):
        self.contypes = { }
        OpenIPMI.parse_args_iter_help(self)
        if (len(self.contypes) == 0):
            return
        
        wx.Panel.__init__(self, parent, -1, size=wx.Size(400, 300))
        self.parent = parent
        self.sizer = wx.BoxSizer(wx.VERTICAL)
        sizer = self.sizer
        self.enable = enable;
        if (not enable):
            self.enable_box = wx.CheckBox(self, -1, "Enable")
            sizer.Add(self.enable_box, 0, wx.ALIGN_CENTRE | wx.ALL, 5);
            pass

        self.contype = wx.RadioBox(self, -1, "Connection Type",
                                   wx.DefaultPosition, wx.DefaultSize,
                                   self.contypes.keys(), 2, wx.RA_SPECIFY_COLS)
        wx.EVT_RADIOBOX(self, self.contype.GetId(), self.selectType)
        self.sizer.Add(self.contype, 0, wx.ALIGN_CENTRE, 2)

        self.coninfos = [ ]
        self.currcon = 0

        show = True
        panel = wx.Panel(self, -1, size=wx.Size(400, 200))
        self.sizer.Add(panel, 0, wx.ALIGN_CENTRE, 0)
        for ct in self.contypes.keys():
            cti = ConnTypeInfo(ct, panel)
            if (show):
                cti.Show(True)
                show = False
            else:
                cti.Show(False)
                pass
            self.coninfos.append(cti)
            pass

        self.SetSizer(self.sizer)
        return

    def parse_args_iter_help_cb(self, name, help):
        self.contypes[name] = help
        return

    def selectType(self, event):
        oldcurr = self.currcon
        self.currcon = event.GetInt()
        self.coninfos[oldcurr].Show(False)
        self.coninfos[self.currcon].Show(True)
        self.parent.Layout()
        return

    def FillinConn(self):
        if (not self.enable):
            if (not self.enable_box.IsChecked()):
                return None
            pass
        cti = self.coninfos[self.contype.GetSelection()]
        return cti.SetupArgs()

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
        wx.EVT_BUTTON(self, cancel.GetId(), self.cancel)
        bbox.Add(cancel, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        ok = wx.Button(self, -1, "Ok")
        wx.EVT_BUTTON(self, ok.GetId(), self.ok)
        bbox.Add(ok, 0, wx.ALIGN_LEFT | wx.ALL, 5);
        self.sizer.Add(bbox, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.status = gui_errstr.ErrStr(self)
        self.sizer.Add(self.status, 0, wx.ALIGN_LEFT | wx.ALL | wx.GROW, 2)

        self.conn = [ ConnInfo(self, mainhandler),
                      ConnInfo(self, mainhandler, False) ]
        self.sizer.Add(self.conn[0], 0, wx.ALIGN_CENTRE | wx.ALL, 2)
        self.sizer.Add(self.conn[1], 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        self.SetSizer(self.sizer)

        wx.EVT_CLOSE(self, self.OnClose)
        
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
        self.status.SetError("")
        name = str(self.name.GetValue())
        if (name == ""):
            self.status.SetError("No name specified")
            return
        try:
            args = [ self.conn[0].FillinConn() ]
            arg = self.conn[1].FillinConn()
            if (arg != None):
                args.append(arg);
                pass
            pass
        except:
            self.status.SetError("Error handling connection arguments")
            return
        domain_id = OpenIPMI.open_domain3(name, [], args, None, None)
        if (domain_id == None):
            self.status.SetError("Error opening domain")
            return

        self.Close(True)

    def OnClose(self, event):
        self.Destroy()

