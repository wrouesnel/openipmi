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

class List(Tix.DialogShell):
    def __init__(self, name, columns):
        Tix.DialogShell.__init__(self, title=name)

        slist = Tix.ScrolledHList(self,
                                  options=("hlist.header 1"
                                           + " hlist.itemtype text"
                                           + " hlist.columns "
                                           + str(len(columns))),
                                  width=500, height=500)
        listc = slist.hlist
        self.listc = listc
        slist.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        
        i = 0
        for c in columns:
            listc.header_create(i, text=c[0])
            listc.column_width(i, c[1])
            i += 1
            pass
        
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

        listc.bind("<Button-3>", self.ListMenu)

        self.bind("<Destroy>", self.OnDestroy)

        self.list_hash = { }
        self.currkey = 0

        return

    def AfterDone(self):
        self.popup()
        return

    def Close(self):
        self.destroy()
        return

    def OnDestroy(self, event):
        if (hasattr(self, "do_on_close")):
            self.do_on_close()
            pass
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
        self.listc.delete_entry(key)
        del self.list_hash[key]
        return

    def Append(self, name, values, data=None):
        key = str(self.currkey)
        self.currkey += 1
        self.listc.add(key, text=name)
        self.list_hash[key] = data
        i = 1
        for v in values:
            if (v != None):
                self.listc.item_create(key, i, text=str(v))
            i += 1
            pass
        return key

    def SetColumn(self, idx, colnum, value):
        self.listc.item_configure(idx, colnum, text=value)
        return

    def SetError(self, str):
        self.errstr.SetError(str)
        return

    def add_data(self, name, values, data=None):
        idx = self.Append(name, values, data);
        if (data != None):
            data.SetItem(idx)
            pass
        return idx

    def DeleteAllItems(self):
        self.listc.delete_all()
        self.list_hash = { }
        self.currkey = 0
        return
    
    pass
