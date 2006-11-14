# gui_treelist.py
#
# A tree/list widget
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

class TreeList(Tix.Toplevel):
    def __init__(self, name, root, columns):
        Tix.Toplevel.__init__(self)
        self.title(name)

        self.numcolumns = len(columns)
        
        stree = Tix.Tree(self,
                         options=("hlist.columns " + str(self.numcolumns)
                                  + " hlist.itemtype text"
                                  + " hlist.header 1"
                                  + " hlist.selectForeground black"
                                  + " hlist.selectBackground beige"),
                                  width=500, height=500)
        self.stree = stree
        tree = stree.hlist
        i = 0
        for c in columns:
            tree.header_create(i, text=c[0])
            tree.column_width(i, c[1])
            i += 1
            pass
        stree.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        
        self.errstr = gui_errstr.ErrStr(self)
        self.errstr.pack(side=Tix.TOP, fill=Tix.X, expand=1)
        
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
        if hasattr(self, "refresh"):
            bbox.add("refresh", text="Refresh", command=self.refresh)
            pass
        if hasattr(self, "clear"):
            bbox.add("clear", text="Clear", command=self.clear)
            pass
        bbox.pack(side=Tix.TOP, fill=Tix.X, expand=1)

        tree.bind("<Button-3>", self.TreeMenu)

        self.bind("<Destroy>", self.OnDestroy)
        
        self.bind("<MouseWheel>", self.Wheel)
        if (gui.winsys == "x11"):
            self.bind("<Button-4>", self.ButtonUp)
            self.bind("<Button-5>", self.ButtonDown)
            pass

        self.treeroot = ""
        self.tree = tree
        self.treehash = { }
        self.currkey = 0
        return

    def Wheel(self, event):
        self.tree.yview("scroll", -(event.delta / 20), "units")
        return
    
    def ButtonUp(self, event):
        event.delta = 120
        self.Wheel(event);
        return
    
    def ButtonDown(self, event):
        event.delta = -120
        self.Wheel(event);
        return
    
    def ExpandItem(self, item):
        children = self.stree.hlist.info_children(item)
        for child in children:
            self.stree.open(child)
            self.ExpandItem(child)
            pass
        return
        
    def Close(self):
        self.destroy()
        return

    def OnDestroy(self, event):
        if (hasattr(self, "do_on_close")):
            self.do_on_close()
            pass
        for i in self.treehash.values():
            if (hasattr(i, "do_on_close")):
                i.do_on_close()
                pass
            pass
        self.treehash = { }
        return

    def TreeMenu(self, event):
        w = event.widget
        key = w.nearest(event.y)
        data = self.treehash[key]
        if (data and hasattr(data, "HandleMenu")):
            data.HandleMenu(event, key, event)
            pass
        return

    def AfterDone(self):
        return

    def Append(self, node, name, values, data=None, before=None):
        hide = False
        if (node == ""):
            key = str(self.currkey)
        else:
            key = node + "." + str(self.currkey)
            mode = self.stree.getmode(node)
            if (mode == "none"):
                self.stree.setmode(node, "open")
                hide = True
                pass
            elif (mode == "open"):
                hide = True
                pass
            pass
        self.currkey += 1
        if (before != None):
            self.tree.add(key, text=name, before=before)
            pass
        else:
            self.tree.add(key, text=name)
            pass
        if (hide):
            self.tree.hide_entry(key)
            pass
        i = 1
        for v in values:
            if (v != None):
                self.tree.item_create(key, i, text=str(v))
            else:
                self.tree.item_create(key, i)
                pass
            i += 1
            pass
        for j in range(i, self.numcolumns):
            self.tree.item_create(key, j)
            pass
        self.treehash[key] = data
        return key

    def Remove(self, key):
        self.stree.hlist.delete_entry(key)
        del self.treehash[key]
        pass

    def RemoveAll(self):
        self.stree.hlist.delete_all()
        for i in self.treehash.values():
            if (hasattr(i, "do_on_close")):
                i.do_on_close()
                pass
            pass
        self.treehash = { }
        pass

    def SetColumn(self, node, value, colnum):
        self.tree.item_configure(node, colnum, text=value)
        return

    def GetColumn(self, node, colnum):
        return self.tree.item_cget(node, colnum, "-text")

    def SetError(self, str):
        self.errstr.SetError(str)
        return

    def add_data(self, parent, name, value, data=None, before=None):
        item = self.Append(parent, name, value, data, before);
        if (data != None):
            data.SetItem(item)
            pass
        return item

    pass
