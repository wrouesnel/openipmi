# gui_setdialog.py
#
# openipmi GUI handling for a normal dialog
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

import Tix
import gui_errstr

def isbool(v):
    return type(v) == type(True)
def isint(v):
    return type(v) == type(0)

class SetDialog(Tix.Toplevel):
    def __init__(self, name, default, count, handler, labels=None,
                 longtext=False):
        self.handler = handler
        Tix.Toplevel.__init__(self)
        self.title(name)
        self.longtext = longtext

        sw = Tix.ScrolledWindow(self)
        self.values = sw.window
        if (labels == None):
            if (count == 1):
                label = Tix.Label(self.values, text="Value:")
            else:
                label = Tix.Label(self.values, text="Value(s):")
                pass
            label.grid(row=0, column=0, sticky="e")
            self.fields = [ ]
            row = 0
            for i in range(0, count):
                if (isbool(default[i])):
                    field = Tix.BooleanVar()
                    field.set(default[i])
                    w = Tix.Checkbutton(self.values, variable=field)
                    pass
                elif longtext:
                    field = Tix.Text(self.values)
                    field.insert("1.0", str(default[i]))
                    w = field
                else:
                    field = Tix.Entry(self.values)
                    field.insert("0", str(default[i]))
                    w = field
                    pass
                w.grid(row=row, column=1, sticky="ew")
                row += 1
                self.fields.append(field)
                pass
            pass
        else:
            self.fields = [ ]
            row = 0
            for i in range(0, count):
                label = Tix.Label(self.values, text=labels[i])
                label.grid(row=row, column=0)
                if (isbool(default[i])):
                    field = Tix.BooleanVar()
                    field.set(default[i])
                    w = Tix.Checkbutton(self.values, variable=field)
                    pass
                elif longtext:
                    field = Tix.Text(self.values)
                    field.insert("1.0", str(default[i]))
                    w = field
                else:
                    field = Tix.Entry(self.values)
                    field.insert("0", str(default[i]))
                    w = field
                    pass
                self.fields.append(field)
                w.grid(row=row, column=1, sticky="ew")
                row += 1
                pass
            pass

        sw.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        
        self.errstr = gui_errstr.ErrStr(self)
        self.errstr.pack(side=Tix.TOP, fill=Tix.X, expand=1)

        bbox = Tix.ButtonBox(self)
        bbox.add("cancel", text="Cancel", command=lambda w=self: w.cancel())
        bbox.add("ok", text="Ok", command=lambda w=self: w.ok())
        bbox.pack(side=Tix.BOTTOM, fill=Tix.X, expand=1)

        self.bind("<Destroy>", self.OnDestroy)
        return
    
    def OnDestroy(self, event):
        if (hasattr(self, "do_on_close")):
            self.do_on_close()
            pass
        self.handler = None
        return

    def cancel(self):
        self.destroy()
        return

    def ok(self):
        vals = [ ]
        for f in self.fields:
            if (self.longtext):
                v = f.get("1.0", "end")
                pass
            else:
                v = f.get()
                pass
            if (isint(v)):
                # Sometime the values from BooleanVar come back as ints.
                v = bool(v)
            elif (not isbool(v)):
                v = v.strip()
                pass
            vals.append(v)
            pass
        try:
            err = self.handler.ok(vals)
            if (err != None):
                self.errstr.SetError(err)
                return
            pass
        except:
            self.errstr.SetError("Value invalid")
            return
        self.destroy()
        return

    pass
