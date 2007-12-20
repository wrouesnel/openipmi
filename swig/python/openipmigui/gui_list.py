# gui_list.py
#
# openipmi GUI handling for a list
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
import gui

# A list widget that can be embedded in something else
class SubList(Tix.ScrolledHList):
    def __init__(self, parent, columns, options, width, height):
        Tix.ScrolledHList.__init__(self, parent,
                                   options=options, width=width, height=height)
        
        i = 0
        for c in columns:
            self.hlist.header_create(i, text=c[0])
            self.hlist.column_width(i, c[1])
            i += 1
            pass
        
        self.list_hash = { }
        self.currkey = 0

        self.hlist.bind("<Button-3>", self.ListMenu)

        self.bind("<Destroy>", self.OnDestroy)

        self.hlist.bind("<MouseWheel>", self.Wheel)
        if (gui.winsys == "x11"):
            self.hlist.bind("<Button-4>", self.ButtonUp)
            self.hlist.bind("<Button-5>", self.ButtonDown)
            pass

        return

    def Wheel(self, event):
        self.hlist.yview("scroll", -(event.delta / 20), "units")
        return
    
    def ButtonUp(self, event):
        event.delta = 120
        self.Wheel(event);
        return
    
    def ButtonDown(self, event):
        event.delta = -120
        self.Wheel(event);
        return
    
    def OnDestroy(self, event):
        self.list_hash = None
        return

    def ListMenu(self, event):
        w = event.widget
        key = w.nearest(event.y)
        data = self.list_hash[key]
        if (data and hasattr(data, "HandleMenu")):
            data.HandleMenu(event, key, event)
            pass
        return

    def DelItem(self, key):
        self.hlist.delete_entry(key)
        del self.list_hash[key]
        return

    def Append(self, name, values, data=None):
        key = str(self.currkey)
        self.currkey += 1
        self.hlist.add(key, text=name)
        self.list_hash[key] = data
        i = 1
        for v in values:
            if (v != None):
                self.hlist.item_create(key, i, text=str(v))
            i += 1
            pass
        return key

    def SetColumn(self, idx, colnum, value):
        self.hlist.item_configure(idx, colnum, text=value)
        return

    def SetColumnStyle(self, node, colnum, style):
        self.hlist.item_configure(node, colnum, style=style)
        return

    def add_data(self, name, values, data=None):
        idx = self.Append(name, values, data);
        if (data != None):
            data.SetItem(idx)
            pass
        return idx

    def DeleteAllItems(self):
        self.hlist.delete_all()
        self.list_hash = { }
        self.currkey = 0
        return
    
    pass

# A top-level list
class List(Tix.Toplevel):
    def __init__(self, name, columns):
        Tix.Toplevel.__init__(self)
        self.title(name)

        slist = SubList(self,
                        columns,
                        options=("hlist.header 1"
                                 + " hlist.itemtype text"
                                 + (" hlist.columns "
                                    + str(len(columns)))
                                 + " hlist.selectForeground black"
                                 + " hlist.selectBackground beige"),
                        width=600, height=500)
        slist.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        self.slist = slist
        
        self.errstr = gui_errstr.ErrStr(self)
        self.errstr.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        
        bbox = Tix.ButtonBox(self)
        if hasattr(self, "ok"):
            bbox.add("ok", text="Ok", command=self.ok)
            pass
        if hasattr(self, "save"):
            bbox.add("save", text="Save", command=self.save)
            pass
        if hasattr(self, "cancel"):
            bbox.add("cancel", text="Cancel", command=self.cancel)
            pass
        if hasattr(self, "clear"):
            bbox.add("clear", text="Clear", command=self.clear)
            pass
        bbox.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)

        self.bind("<Destroy>", self.OnDestroy)

        return

    def AfterDone(self):
        return

    def Close(self):
        self.destroy()
        return

    def OnDestroy(self, event):
        if (hasattr(self, "do_on_close")):
            self.do_on_close()
            pass
        return

    def DelItem(self, key):
        self.slist.DelItem(key)
        return

    def Append(self, name, values, data=None):
        return self.slist.Append(name, values, data)

    def SetColumn(self, idx, colnum, value):
        self.slist.SetColumn(idx, colnum, value)
        return

    def add_data(self, name, values, data=None):
        return self.slist.add_data(name, values, data)

    def DeleteAllItems(self):
        return self.slist.DeleteAllItems()
        return
    
    def SetError(self, str):
        self.errstr.SetError(str)
        return

    # Pass the rest of the functions on to the base list.
    def DelItem(self, key):
        self.slist.DelItem(key)
        return

    def Append(self, name, values, data=None):
        return self.slist.Append(name, values, data)

    def SetColumn(self, idx, colnum, value):
        self.slist.SetColumn(idx, colnum, value)
        return

    def add_data(self, name, values, data=None):
        return self.slist.add_data(name, values, data)

    def DeleteAllItems(self):
        return self.slist.DeleteAllItems()
        return
    
    pass
