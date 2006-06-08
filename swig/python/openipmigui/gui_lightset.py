# gui_lightset.py
#
# openipmi GUI handling for light setting
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

class LightSet(Tix.Toplevel):
    def __init__(self, name, num_vals, light_list, vals, handler):
        self.handler = handler
        self.light_list = light_list
        Tix.Toplevel.__init__(self)
        self.title(name)

        svalues = Tix.ScrolledWindow(self)
        self.values = svalues.window
        self.lights = [ ]

        row = 0
        for i in range(0, num_vals):
            if (len(vals) <= i):
                ivals = ("", "black", '0', '1')
            else:
                ivals = vals[i]
                pass

            label = Tix.Label(self.values, text="Light " + str(i))
            label.grid(row=row, column=0, sticky="e")
            if (light_list[i][0]):
                lc = Tix.BooleanVar()
                lcw = Tix.Checkbutton(self.values, text="Local Control",
                                      variable=lc)
                lc.set(ivals[0] == "lc")
                lcw.grid(row=row, column=1, sticky="ew")
                row += 1
            else:
                lc = None
                pass

            color = EnumHolder()
            colorw = Tix.Select(self.values, label="Color", allowzero=0,
                               radio=1, command=color.SelectType)
            for v in light_list[i][1]:
                colorw.add(v, text=v)
                pass
            colorw.configure(value=ivals[1])
            colorw.grid(row=row, column=1, sticky="ew")
            row += 1

            ontime = Tix.LabelEntry(self.values, label="On Time")
            ontime.entry.insert("0", ivals[2])
            ontime.grid(row=row, column=1, sticky="ew")
            row += 1
            ontime = ontime.entry

            offtime = Tix.LabelEntry(self.values, label="Off Time")
            offtime.entry.insert("0", ivals[3])
            offtime.grid(row=row, column=1, sticky="ew")
            row += 1
            offtime = offtime.entry

            self.lights.append( (lc, color, ontime, offtime) )
            pass
            
        svalues.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)

        bbox = Tix.ButtonBox(self)
        bbox.add("cancel", text="Cancel", command=lambda w=self: w.cancel())
        bbox.add("ok", text="Ok", command=lambda w=self: w.ok_press())
        bbox.pack(side=Tix.BOTTOM, fill=Tix.X, expand=1)

        self.bind("<Destroy>", self.OnDestroy)
        return

    def cancel(self):
        self.destroy()
        return

    def ok_press(self):
        val = [ ]
        try:
            i = 0;
            for f in self.lights:
                lc = ""
                if (f[0] != None) and f[0].get():
                    lc = str("lc")
                color = str(f[1].get())
                ontime = str(f[2].get())
                offtime = str(f[3].get())
                val.append(' '.join([lc, color, ontime, offtime]))
                i = i + 1
                pass

            self.handler.ok(val)
            pass
        except Exception, e:
            print str(e)
            return
        self.destroy()
        return

    def OnDestroy(self, event):
        if (hasattr(self, "do_on_close")):
            self.do_on_close()
            pass
        self.handler = None
        self.light_list = None
        self.lights = None
        return

    pass
