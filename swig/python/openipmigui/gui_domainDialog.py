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
import Tix
import OpenIPMI
import _domain
import gui_errstr

class EnumHolder:
    def __init__(self):
        self.value = ""
        return

    def get(self):
        return self.value

    def set(self, val):
        self.value = val

    def SelectType(self, newbutton, selected):
        if (selected == "0"):
            return
        self.value = newbutton
        return
    
    pass

class ConnTypeInfo(Tix.Frame):
    def __init__(self, contype, parent):
        Tix.Frame.__init__(self, parent)
        self.contype = contype
        self.fields = [ ]

        args = OpenIPMI.alloc_empty_args(str(contype))
        self.args = args

        self.errstr = gui_errstr.ErrStr(self)
        self.errstr.pack(side=Tix.TOP, fill=Tix.X, expand=1)

        i = 0
        rv = 0
        frame = None
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
                
                if (vtype[0] == "bool"):
                    if (frame == None):
                        didframe = True
                        frame = Tix.Frame(self)
                        frame.pack(side=Tix.TOP)
                        newframe = frame
                        pass
                    else:
                        newframe = None
                        pass
                    fw = Tix.BooleanVar()
                    w = Tix.Checkbutton(frame, text=name[0], variable=fw)
                    w.pack(side=Tix.LEFT, padx=10)
                    if ((value[0] != None) and (value[0] == "true")):
                        fw.set(True)
                        pass
                    pass
                elif (vtype[0] == "enum"):
                    do_box = False
                    fw = EnumHolder()
                    if (value[0] != None):
                        fw.set(value[0])
                        pass
                    else:
                        fw.set(vrange[0])
                        pass
                    w = Tix.Select(self, label=name[0], allowzero=0, radio=1,
                                   command=fw.SelectType)
                    for v in vrange:
                        w.add(v, text=v)
                        pass
                    newframe = None
                    w.invoke(fw.get())
                    w.pack()
                    pass
                elif (vtype[0] == "str") or (vtype[0] == "int"):
                    if (frame == None):
                        didframe = True
                        frame = Tix.Frame(self)
                        frame.pack(side=Tix.TOP)
                        newframe = frame
                        pass
                    else:
                        newframe = None
                        pass

                    if (value[0] == None):
                        value[0] = ""
                        pass
                    if (password):
                        options="entry.show '*' entry.width 20"
                    else:
                        options="entry.width 20"
                        pass
                    w = Tix.LabelEntry(frame, label=name[0], options=options)
                    w.entry.insert(Tix.END, value[0])
                    w.pack(side=Tix.LEFT, padx=10)
                    fw = w.entry
                    pass
                else:
                    i += 1
                    continue
                frame = newframe
                self.fields.append( (i, name[0], vtype[0], fw) )
                pass
            i += 1
            pass

        return

    def SetupArgs(self):
        self.errstr.SetError("")
        args = self.args
        for f in self.fields:
            idx = f[0]
            vtype = f[2]
            fw = f[3]
            if (vtype == "bool"):
                if (fw.get()):
                    val = "true"
                else:
                    val = "false"
                    pass
                pass
            elif (vtype == "enum"):
                val = str(fw.get())
                pass
            elif ((vtype == "str") or (vtype == "int")):
                val = str(fw.get())
                if (val == ""):
                    val = None
                    pass
                pass
            else:
                continue
            rv = args.set_val(idx, None, val);
            if (rv != 0):
                err = ("Error setting field " + f[1] + ": "
                       + OpenIPMI.get_error_string(rv))
                self.errstr.SetError(err)
                raise Exception(err)
            pass
        return args

    def Cleanup(self):
        self.args = None
        return

    pass

class ConnInfo(Tix.ScrolledWindow):
    def __init__(self, parent, mainhandler, enable=True):
        self.contypes = { }
        OpenIPMI.parse_args_iter_help(self)
        if (len(self.contypes) == 0):
            return
        
        Tix.ScrolledWindow.__init__(self, parent, height=300, width=600)
        self.parent = parent
        self.enable = enable;

        if (not enable):
            self.enablevar = Tix.BooleanVar()
            self.enable_box = Tix.Checkbutton(self.window, text="Enable",
                                              variable=self.enablevar)
            self.enable_box.pack(side=Tix.TOP)
            pass

        self.contype = Tix.Select(self.window, label="Connection Type",
                                  radio=1, allowzero=0,
                                  command=self.selectType)
        for key in self.contypes.keys():
            self.contype.add(key, text=key)
            pass
        self.contype.pack(side=Tix.TOP)

        self.coninfos = [ ]

        show = True
        panel = Tix.Frame(self.window)
        panel.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        for ct in self.contypes.keys():
            cti = ConnTypeInfo(ct, panel)
            if (show):
                cti.pack()
                self.currcon = cti
                show = False
                pass
            self.coninfos.append(cti)
            pass

        self.contype.invoke(self.contypes.keys()[0])

        return

    def parse_args_iter_help_cb(self, name, help):
        self.contypes[name] = help
        return

    def selectType(self, newbutton, selected):
        if (selected == "0"):
            return
        self.currcon.pack_forget()
        for cti in self.coninfos:
            if (newbutton == cti.contype):
                self.currcon = cti;
                cti.pack()
                pass
            pass
        return

    def FillinConn(self):
        if (not self.enable):
            if (not self.enablevar.get()):
                return None
            pass
        return self.currcon.SetupArgs()

    def Cleanup(self):
        for cti in self.coninfos:
            cti.Cleanup()
            pass
        self.currcon = None
        return

    pass

class OpenDomainDialog(Tix.Toplevel):
    def __init__(self, mainhandler):
        Tix.Toplevel.__init__(self)
        self.title("Domain Creation Dialog")
        
        self.mainhandler = mainhandler

        self.name = Tix.LabelEntry(self, label="Domain name")
        self.name.pack(side=Tix.TOP, fill=Tix.X, expand=1)

        bbox = Tix.ButtonBox(self)
        bbox.add("cancel", text="Cancel", command=lambda w=self: w.cancel())
        bbox.add("ok", text="Ok", command=lambda w=self: w.ok())
        bbox.pack(side=Tix.BOTTOM, fill=Tix.X, expand=1)

        self.status = gui_errstr.ErrStr(self)
        self.status.pack(side=Tix.BOTTOM, fill=Tix.X, expand=1)

        self.conn = [ ConnInfo(self, mainhandler),
                      ConnInfo(self, mainhandler, False) ]
        self.conn[0].pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        self.conn[1].pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        self.name.entry.focus()

        self.bind("<Destroy>", self.OnDestroy)

        return

    def OnDestroy(self, event):
        # This doesn't get cleaned up properly by Python til after
        # exit, but we need to make sure the args get freed now, or
        # it won't be freed until after the OS handler is destroyed.
        for c in self.conn:
            c.Cleanup()
            pass
        return
    
    def cancel(self):
        self.destroy()
        return

    def ok(self):
        self.status.SetError("")
        name = str(self.name.entry.get())
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
        except Exception, e:
            self.status.SetError("Error handling connection arguments")
            import sys, traceback
            t, v, b = sys.exc_info()
            bl = traceback.format_tb(b)
            b = ""
            for x in bl:
                b += "\n" + x
            self.mainhandler.log("EINF", "Connection Argument Handling error: "
                                 + str(t) + ":" + str(v) + ":" + b)
            return
        domain_id = OpenIPMI.open_domain3(name, [], args, None, None)
        if (domain_id == None):
            self.status.SetError("Error opening domain")
            return

        self.destroy()
        return

    pass
