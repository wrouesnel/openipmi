# gui.py
#
# main openipmi GUI handling
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
import _saveprefs
import _oi_logging
import gui_domainDialog

init_treenamewidth = 150
init_sashposition = 500
init_bsashposition = 400
init_windowwidth = 800
init_windowheight = 500
init_logevents = False
init_fullevents = False

refresh_timer_time = 10000

class IPMITreeDummyItem:
    def __init__(self, treestr):
        self.treestr = treestr
        return

    pass

class IPMICloser:
    def __init__(self, ui, count):
        self.ui = ui
        self.count = count
        return

    def domain_cb(self, domain):
        domain.close(self)

    def domain_close_done_cb(self):
        self.count = self.count - 1
        if (self.count == 0):
            #FIXME - _cmdwin.init_history = self.ui.cmdwindow.history
            self.ui.mainhandler.top.destroy()
            pass
        return
    pass

class IPMIGUI(Tix.Frame):
    def __init__(self, top, mainhandler):
        Tix.Frame.__init__(self, top, bd=2, relief=Tix.RAISED)

        self.top = top

        self.mainhandler = mainhandler

        self.inactive_style = Tix.DisplayStyle(Tix.TEXT, fg="grey", bg='white',
                                               refwindow=top)
        self.active_style = Tix.DisplayStyle(Tix.TEXT, fg="black", bg="white",
                                             refwindow=top)
        self.critical_style = Tix.DisplayStyle(Tix.TEXT, fg="blue", bg='white',
                                               refwindow=top)
        self.severe_style = Tix.DisplayStyle(Tix.TEXT, fg="red", bg='white',
                                             refwindow=top)
        self.warn_style = Tix.DisplayStyle(Tix.TEXT, fg="yellow", bg='white',
                                           refwindow=top)
        
        self.logeventsv = Tix.IntVar()
        self.logeventsv.set(init_logevents)
        self.logevents = init_logevents
        self.fulleventsv = Tix.IntVar()
        self.fulleventsv.set(init_fullevents)
        OpenIPMI.cmdlang_set_evinfo(self.fulleventsv.get())
        
        fileb = Tix.Menubutton(self, text="File", underline=0, takefocus=0)
        filemenu = Tix.Menu(fileb, tearoff=0)
        fileb["menu"] = filemenu
        filemenu.add_command(label="Exit", underline=1, accelerator="Ctrl+Q",
                             command = lambda self=self: self.quit() )
        top.bind_all("<Control-Q>", self.quit)
        top.bind_all("<Control-q>", self.quit)
        filemenu.add_command(label="Open Domain", underline=1,
                             accelerator="Ctrl+O",
                             command = lambda self=self: self.openDomain() )
        top.bind_all("<Control-O>", self.openDomain)
        top.bind_all("<Control-o>", self.openDomain)
        filemenu.add_command(label="Save Prefs", underline=1,
                             accelerator="Ctrl+S",
                             command = lambda self=self: self.savePrefs() )
        top.bind_all("<Control-S>", self.savePrefs)
        top.bind_all("<Control-s>", self.savePrefs)

        viewb = Tix.Menubutton(self, text="View", underline=0, takefocus=0)
        viewmenu = Tix.Menu(viewb, tearoff=0)
        viewb["menu"] = viewmenu
        viewmenu.add_command(label="Expand All", underline=1,
                             accelerator="Ctrl+E",
                             command = lambda self=self: self.ExpandAll() )
        top.bind_all("<Control-E>", self.ExpandAll)
        top.bind_all("<Control-e>", self.ExpandAll)
        viewmenu.add_command(label="Collapse All", underline=1,
                             accelerator="Ctrl+C",
                             command = lambda self=self: self.CollapseAll() )
        top.bind_all("<Control-C>", self.CollapseAll)
        top.bind_all("<Control-c>", self.CollapseAll)

        setb = Tix.Menubutton(self, text="Settings", underline=0, takefocus=0)
        viewmenu = Tix.Menu(setb, tearoff=0)
        setb["menu"] = viewmenu
        viewmenu.add_checkbutton(label="Enable Events", underline=0,
                                 command=lambda w=self: w.EnableEvents(),
                                 variable=self.logeventsv)
        viewmenu.add_checkbutton(label="Full Event Info", underline=0,
                                 command=lambda w=self: w.FullEventInfo(),
                                 variable=self.fulleventsv)

        vpane = Tix.PanedWindow(self, orientation="vertical",
                                width=init_windowwidth,
                                height=init_windowheight)
        self.vpane = vpane
        objevpane = vpane.add("objectsevents", size=init_bsashposition)
        cmdpane = vpane.add("command")
        hpane = Tix.PanedWindow(objevpane, orientation="horizontal")
        self.hpane = hpane
        objpane = hpane.add("objects", size=init_sashposition)
        evpane = hpane.add("events")

        self.tree = Tix.Tree(objpane, options="hlist.columns 2")
        self.tree.hlist.add("D", itemtype=Tix.TEXT, text="Domains")
        self.tree.setmode("D", "none")
        self.treedata = { }
        self.treedata["D"] = IPMITreeDummyItem("D")
        self.setup_item("D", active=True)
        self.tree.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        self.tree.hlist.bind("<Button-3>", self.TreeMenu)

        self.numloglines = 1
        self.maxloglines = 1000
        self.logwindow = Tix.ScrolledText(evpane)
        self.logwindow.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)
        self.logwindow.text.insert("end", "GUI Log Window")

        self.cmdwindow = Tix.ScrolledText(cmdpane)
        self.cmdwindow.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)

        hpane.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)

        vpane.pack(side=Tix.BOTTOM, fill=Tix.BOTH, expand=1)
        fileb.pack(side=Tix.LEFT)
        viewb.pack(side=Tix.LEFT)
        setb.pack(side=Tix.LEFT)
        
        self.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)

        self.itemval = 0

        self.in_destroy = False

        self.bind("<Destroy>", self.OnDestroy)

        self.last_scan = None
        self.timer_timeout_ms = 200
        top.after(self.timer_timeout_ms, self.Timeout)
        return

    def ReportError(self, str):
        if (self.in_destroy):
            return
        self.SetStatusText(str, 0)
        return
    
    def Timeout(self):
        if (self.in_destroy):
            return
        if (self.last_scan != None):
            next = self.last_scan
        else:
            next = self.tree.hlist.info_next("D")
            pass
        callcount = 0
        checkcount = 0
        while (callcount < 100) and (checkcount < 1000) and (next != ""):
            if (self.tree.hlist.info_hidden(next) == "1"):
                # Not on the screen, ignore it
                next = self.tree.hlist.info_next(next)
                continue
            data = self.treedata[next]
            if (data != None) and (hasattr(data, "DoUpdate")):
                callcount = callcount + 1
                data.DoUpdate()
                pass
            next = self.tree.hlist.info_next(next)
            checkcount = checkcount + 1
            pass
            
        if (next != ""):
            self.last_scan = next
        else:
            self.last_scan = None
            pass
        
        self.top.after(self.timer_timeout_ms, self.Timeout)
        return
        
    def quit(self, event=None):
        self.destroy()
        return

    def OnDestroy(self, event):
        self.in_destroy = True
        self.closecount = len(self.mainhandler.domains)
        if (self.closecount == 0):
            _cmdwin.init_history = self.cmdwindow.history
            self.Destroy()
            return
        closer = IPMICloser(self, self.closecount)
        ds = self.mainhandler.domains.values()
        for v in ds:
            v.domain_id.to_domain(closer)
            pass
        return

    def openDomain(self, event=None):
        dialog = gui_domainDialog.OpenDomainDialog(self.mainhandler)
        return

    def savePrefs(self, event=None):
        self.mainhandler.savePrefs()
        return

    def ExpandItem(self, item):
        (child, cookie) = self.tree.GetFirstChild(item)
        while child.IsOk():
            if self.tree.ItemHasChildren(child):
                self.tree.Expand(child)
                self.ExpandItem(child)
                pass
            (child, cookie) = self.tree.GetNextChild(item, cookie)
            pass
        return
        
    def ExpandAll(self, event=None):
        self.tree.Expand(self.treeroot)
        self.ExpandItem(self.treeroot)
        return
        
    def CollapseItem(self, item):
        (child, cookie) = self.tree.GetFirstChild(item)
        while child.IsOk():
            if self.tree.ItemHasChildren(child):
                self.tree.Collapse(child)
                self.CollapseItem(child)
                pass
            (child, cookie) = self.tree.GetNextChild(item, cookie)
            pass
        return
        
    def CollapseAll(self, event=None):
        self.CollapseItem(self.treeroot)
        return
        
    def EnableEvents(self, event=None):
        self.logevents = self.logeventsv.get() != 0
        print "logevents = " + str(self.logevents)
        return
    
    def FullEventInfo(self, event=None):
        print "fullevents = " + str(self.fulleventsv.get())
        OpenIPMI.cmdlang_set_evinfo(self.fulleventsv.get())
        return
    
    def new_log(self, log):
        if (self.in_destroy):
            return
        self.numloglines += log.count("\n") + 1
        self.logwindow.text.insert("end", "\n" + log)
        overrun = self.numloglines - self.maxloglines
        if (overrun > 0):
            self.logwindow.text.delete("1.0", str(overrun+1)+".0")
            self.numloglines -= overrun
            pass
        return

    def setup_item(self, item, active=False):
        data = self.treedata[item]
        data.active = active
        data.num_warning = 0
        data.num_severe = 0
        data.num_critical = 0
        self.tree.hlist.item_create(item, 1, itemtype=Tix.TEXT, text="",
                                    style=self.active_style)
        if (not active):
            self.tree.hlist.item_configure(item, 0, style=self.inactive_style)
            pass
        else:
            self.tree.hlist.item_configure(item, 0, style=self.active_style)
            pass
        return

    def cleanup_item(self, item):
        if (self.in_destroy):
            return
        data = self.treedata[item]
        if (data == None):
            return
        parent = self.parent_item(item)
        if (parent != None):
            return
        while (data.num_warning > 0):
            data.num_warning = data.num_warning - 1;
            self.decr_item_warning(parent); 
            pass
        while (data.num_severe > 0):
            data.num_severe = data.num_severe - 1;
            self.decr_item_severe(parent); 
            pass
        while (data.num_critical > 0):
            data.num_critical = data.num_critical - 1;
            self.decr_item_critical(parent); 
            pass
        return

    def add_domain(self, d):
        if (self.in_destroy):
            return
        d.name_str = str(d)
        item = "D." + str(self.itemval)
        self.itemval += 1
        d.treeroot = item
        self.tree.hlist.add(d.treeroot, itemtype=Tix.TEXT, text=d.name_str)
        self.tree.setmode(d.treeroot, "open")
        self.tree.close(d.treeroot)
        self.treedata[d.treeroot] = d
        self.setup_item(d.treeroot, active=True)
        
        lstr = d.treeroot + ".E"
        self.tree.hlist.add(lstr, itemtype=Tix.TEXT, text="Entities")
        self.tree.setmode(lstr, "none")
        self.tree.close(lstr)
        self.tree.hlist.hide_entry(lstr)
        self.treedata[lstr] = IPMITreeDummyItem(lstr)
        self.setup_item(lstr, active=True)
        
        lstr = d.treeroot + ".M"
        self.tree.hlist.add(lstr, itemtype=Tix.TEXT, text="MCs")
        self.tree.setmode(lstr, "none")
        self.tree.close(lstr)
        self.tree.hlist.hide_entry(lstr)
        self.treedata[lstr] = IPMITreeDummyItem(lstr)
        self.setup_item(lstr, active=True)
        
        lstr = d.treeroot + ".C"
        self.tree.hlist.add(lstr, itemtype=Tix.TEXT, text="Connections")
        self.tree.setmode(lstr, "none")
        self.tree.close(lstr)
        self.tree.hlist.hide_entry(lstr)
        self.treedata[lstr] = IPMITreeDummyItem(lstr)
        self.setup_item(lstr, active=True)
        
        return

    def item_sethide(self, parent, item):
        mode = self.tree.getmode(parent)
        if (mode == "open"):
            self.tree.hlist.hide_entry(item)
        elif (mode == "close"):
            pass
        else:
            self.tree.setmode(parent, "open")
            self.tree.hlist.hide_entry(item)
            pass
        return

    def prepend_item(self, o, name, value, data=None):
        if (self.in_destroy):
            return
        item = o.treeroot + '.' + str(self.itemval)
        if (data == None):
            data = IPMITreeDummyItem(item)
            pass
        data.name_str = name
        self.itemval += 1
        self.tree.hlist.add(item, itemtype=Tix.TEXT, text=name + ":", at=0)
        mode = self.tree.getmode(o.treeroot)
        self.item_sethide(o.treeroot, item)
        if (value == None):
            self.tree.hlist.item_create(item, 1, itemtype=Tix.TEXT, text="",
                                        style=self.active_style)
            self.tree.hlist.item_configure(item, 0, style=self.inactive_style)
        else:
            self.tree.hlist.item_create(item, 1, itemtype=Tix.TEXT, text=value,
                                        style=self.active_style)
            self.tree.hlist.item_configure(item, 0, style=self.active_style)
            pass
        self.treedata[item] = data
        return item

    def append_item(self, o, name, value, data=None, parent=None):
        if (self.in_destroy):
            return
        if (parent == None):
            parent = o.treeroot
            pass
        item = parent + '.' + str(self.itemval)
        if (data == None):
            data = IPMITreeDummyItem(item)
            pass
        data.name_str = name
        self.itemval += 1
        self.tree.hlist.add(item, itemtype=Tix.TEXT, text=name + ":")
        mode = self.tree.getmode(parent)
        if (mode == "open"):
            self.tree.hlist.hide_entry(item)
        elif (mode == "close"):
            pass
        else:
            self.tree.setmode(parent, "open")
            self.tree.hlist.hide_entry(item)
            pass
        if (value == None):
            self.tree.hlist.item_create(item, 1, itemtype=Tix.TEXT, text="",
                                        style=self.active_style)
            self.tree.hlist.item_configure(item, 0, style=self.inactive_style)
        else:
            self.tree.hlist.item_create(item, 1, itemtype=Tix.TEXT, text=value,
                                        style=self.active_style)
            self.tree.hlist.item_configure(item, 0, style=self.active_style)
            pass
        self.treedata[item] = data
        return item

    def set_item_text(self, item, value):
        if (self.in_destroy):
            return
        data = self.treedata[item]
        name = data.name_str
        if (value == None):
            self.tree.hlist.item_configure(item, 1, style=self.inactive_style,
                                           text="")
            pass
        else:
            self.tree.hlist.item_configure(item, 1, text=value)
            if (hasattr(data, "active")):
                if (data.active):
                    self.set_item_color(item)
                    pass
                pass
            else:
                self.tree.hlist.item_configure(item, 0, style=self.active_style)
                pass
            pass
        return

    def set_item_inactive(self, item):
        if (self.in_destroy):
            return
        data = self.treedata[item]
        data.active = False
        self.tree.hlist.item_configure(item, 0, style=self.inactive_style)
        return

    def set_item_active(self, item):
        if (self.in_destroy):
            return
        data = self.treedata[item]
        data.active = True
        self.set_item_color(item)
        return

    def parent_item(self, item):
        idx = item.rfind(".")
        if (idx == -1):
            return None
        return item[0:idx]
        
    def set_item_color(self, item):
        data = self.treedata[item]
        if (data.num_critical > 0):
            self.tree.hlist.item_configure(item, 0, style=self.critical_style)
            return
        if (data.num_severe > 0):
            self.tree.hlist.item_configure(item, 0, style=self.severe_style)
            return
        if (data.num_warning > 0):
            self.tree.hlist.item_configure(item, 0, style=self.warn_style)
            return
        
        self.tree.hlist.item_configure(item, 0, style=self.active_style)
        return
        
    def incr_item_warning(self, item):
        if (self.in_destroy):
            return
        parent = self.parent_item(item)
        if (parent != None):
           self.incr_item_warning(parent); 
           pass
        data = self.treedata[item]
        if (data == None):
            return
        data.num_warning = data.num_warning + 1
        if (not data.active):
            return
        if (data.num_critical > 0):
            return
        if (data.num_severe > 0):
            return
        if (data.num_warning == 1):
            self.tree.hlist.item_configure(item, 0, style=self.warn_style)
            pass
        return
        
    def decr_item_warning(self, item):
        if (self.in_destroy):
            return
        parent = self.parent_item(item)
        if (parent != None):
           self.decr_item_warning(parent); 
           pass
        data = self.treedata[item]
        if (data == None):
            return
        data.num_warning = data.num_warning - 1
        if (not data.active):
            return
        if (data.num_critical > 0):
            return
        if (data.num_severe > 0):
            return
        if (data.num_warning > 0):
            return
        self.tree.hlist.item_configure(item, 0, style=self.active_style)
        return
        
    def incr_item_severe(self, item):
        if (self.in_destroy):
            return
        parent = self.parent_item(item)
        if (parent != None):
           self.incr_item_severe(parent); 
           pass
        data = self.treedata[item]
        if (data == None):
            return
        data.num_severe = data.num_severe + 1
        if (not data.active):
            return
        if (data.num_critical > 0):
            return
        if (data.num_severe == 1):
            self.tree.hlist.item_configure(item, 0, style=self.severe_style)
            pass
        return
        
    def decr_item_severe(self, item):
        if (self.in_destroy):
            return
        parent = self.parent_item(item)
        if (parent != None):
           self.decr_item_severe(parent); 
           pass
        data = self.treedata[item]
        if (data == None):
            return
        data.num_severe = data.num_severe - 1
        if (not data.active):
            return
        if (data.num_critical > 0):
            return
        if (data.num_severe > 0):
            return
        if (data.num_warning > 0):
            self.tree.hlist.item_configure(item, 0, style=self.warn_style)
            return
        self.tree.hlist.item_configure(item, 0, style=self.active_style)
        return
        
    def incr_item_critical(self, item):
        if (self.in_destroy):
            return
        parent = self.parent_item(item)
        if (parent != None):
           self.incr_item_critical(parent); 
           pass
        data = self.treedata[item]
        if (data == None):
            return
        data.num_critical = data.num_critical + 1
        if (not data.active):
            return
        if (data.num_critical == 1):
            self.tree.hlist.item_configure(item, 0, style=self.critical_style)
            pass
        return
        
    def decr_item_critical(self, item):
        if (self.in_destroy):
            return
        parent = self.parent_item(item)
        if (parent != None):
           self.decr_item_critical(parent); 
           pass
        data = self.treedata[item]
        if (data == None):
            return
        data.num_critical = data.num_critical - 1
        if (not data.active):
            return
        if (data.num_critical > 0):
            return
        if (data.num_severe > 0):
            self.tree.hlist.item_configure(item, 0, style=self.severe_style)
            return
        if (data.num_warning > 0):
            self.tree.hlist.item_configure(item, 0, style=self.warn_style)
            return
        self.tree.hlist.item_configure(item, 0, style=self.active_style)
        return
        
    def get_item_pos(self, item):
        rect = self.tree.GetBoundingRect(item)
        if (rect == None):
            return None
        # FIXME - why do I have to add 25?
        return wx.Point(rect.GetLeft(), rect.GetBottom()+25)

    def TreeMenu(self, event):
        w = event.widget
        item = w.nearest(event.y)
        data = self.treedata[item]
        if (data != None) and (hasattr(data, "HandleMenu")):
            data.HandleMenu(event)
            pass
        return

    # FIXME - expand of parent doesn't affect children...
    def TreeExpanded(self, event):
        item = event.GetItem()
        data = self.tree.GetPyData(item)
        if (data != None) and (hasattr(data, "HandleExpand")):
            data.HandleExpand(event)
            pass
        return

    def remove_domain(self, d):
        if (self.in_destroy):
            return
        if (hasattr(d, "treeroot")):
            self.cleanup_item(d.treeroot)
            self.tree.hlist.delete_entry(d.treeroot)
            pass
        return

    def add_connection(self, d, c):
        if (self.in_destroy):
            return
        parent = d.treeroot + ".C"
        item = parent + '.' + str(self.itemval)
        self.itemval += 1
        c.treeroot = item
        c.name_str = str(c)
        self.tree.hlist.add(item, itemtype=Tix.TEXT, text=c.name_str)
        self.tree.setmode(item, "none")
        self.tree.close(item)
        self.item_sethide(parent, item)
        self.treedata[item] = c
        self.setup_item(item, active=True)
        return
        
    def add_port(self, c, p):
        if (self.in_destroy):
            return
        item = c.treeroot + '.' + str(self.itemval)
        self.itemval += 1
        p.treeroot = item
        p.name_str = str(p)
        self.tree.hlist.add(item, itemtype=Tix.TEXT, text=p.name_str)
        self.tree.setmode(item, "none")
        self.tree.close(item)
        self.item_sethide(c.treeroot, item)
        self.treedata[item] = p
        self.setup_item(item, active=True)
        return
        
    def add_entity(self, d, e, parent=None):
        if (self.in_destroy):
            return
        if (parent == None):
            parent = d.treeroot + ".E"
            pass
        else:
            parent = parent.treeroot
            pass
        e.name_str = str(e)
        item = parent + '.' + str(self.itemval)
        self.itemval += 1
        e.treeroot = item
        self.tree.hlist.add(item, itemtype=Tix.TEXT, text=e.name_str)
        self.tree.setmode(item, "open")
        self.tree.close(item)
        self.item_sethide(parent, item)
        self.treedata[item] = e
        self.setup_item(item)

        lstr = item + ".S"
        self.tree.hlist.add(lstr, itemtype=Tix.TEXT, text="Sensors")
        self.tree.setmode(lstr, "none")
        self.tree.close(lstr)
        self.tree.hlist.hide_entry(lstr)
        self.treedata[lstr] = IPMITreeDummyItem(lstr)
        self.setup_item(lstr, active=True)

        lstr = item + ".C"
        self.tree.hlist.add(lstr, itemtype=Tix.TEXT, text="Controls")
        self.tree.setmode(lstr, "none")
        self.tree.close(lstr)
        self.tree.hlist.hide_entry(lstr)
        self.treedata[lstr] = IPMITreeDummyItem(lstr)
        self.setup_item(lstr, active=True)
        return

    def reparent_entity(self, d, e, parent):
        if (self.in_destroy):
            return
        self.add_entity(d, e, parent)
        return
    
    def remove_entity(self, e):
        if (self.in_destroy):
            return
        if (hasattr(e, "treeroot")):
            self.cleanup_item(e.treeroot)
            self.tree.hlist.delete_entry(e.treeroot)
            del self.treedata[e.treeroot]
            pass
        return

    def add_mc(self, d, m):
        if (self.in_destroy):
            return
        parent = d.treeroot + ".M"
        m.name_str = str(m)
        item = parent + "." + str(self.itemval)
        self.itemval += 1
        m.treeroot = item
        self.tree.hlist.add(item, itemtype=Tix.TEXT, text=m.name_str)
        self.tree.setmode(item, "none")
        self.tree.close(item)
        self.item_sethide(parent, item)
        self.treedata[item] = m
        self.setup_item(item)
        return

    def remove_mc(self, m):
        if (self.in_destroy):
            return
        if (hasattr(m, "treeroot")):
            self.cleanup_item(m.treeroot)
            self.tree.hlist.delete_entry(m.treeroot)
            del self.treedata[m.treeroot]
            pass
        return

    def add_sensor(self, e, s):
        if (self.in_destroy):
            return
        parent = e.treeroot + ".S"
        s.name_str = str(s)
        item = parent + "." + str(self.itemval)
        self.itemval += 1
        s.treeroot = item
        self.tree.hlist.add(item, itemtype=Tix.TEXT, text=s.name_str)
        self.tree.setmode(item, "none")
        self.tree.close(item)
        self.item_sethide(parent, item)
        self.treedata[item] = s
        self.setup_item(item, active=True)
        return

    def remove_sensor(self, s):
        if (self.in_destroy):
            return
        if (hasattr(s, "treeroot")):
            self.cleanup_item(s.treeroot)
            self.tree.hlist.delete_entry(s.treeroot)
            del self.treedata[s.treeroot]
            pass
        return

    def add_control(self, e, c):
        if (self.in_destroy):
            return
        parent = e.treeroot + ".C"
        c.name_str = str(c)
        item =  parent + "." + str(self.itemval)
        self.itemval += 1
        c.treeroot = item
        self.tree.hlist.add(item, itemtype=Tix.TEXT, text=c.name_str)
        self.tree.setmode(item, "none")
        self.tree.close(item)
        self.item_sethide(parent, item)
        self.treedata[item] = c
        self.setup_item(item, active=True)
        return

    def remove_control(self, c):
        if (self.in_destroy):
            return
        if (hasattr(c, "treeroot")):
            self.cleanup_item(c.treeroot)
            self.tree.hlist.delete_entry(c.treeroot)
            del self.treedata[c.treeroot]
            pass
        return

    # XML preferences handling
    def getTag(self):
        return "guiparms"

    def SaveInfo(self, doc, elem):
        elem.setAttribute("windowwidth", str(self.vpane.winfo_width()))
        elem.setAttribute("windowheight", str(self.vpane.winfo_height()))
        elem.setAttribute("sashposition",
                          str(self.vpane.panecget("objectsevents", "-size")))
        elem.setAttribute("bsashposition",
                          str(self.hpane.panecget("objects", "-size")))
        #elem.setAttribute("treenamewidth", str(self.tree.GetColumnWidth(0)))
        elem.setAttribute("logevents", str(self.logevents))
        elem.setAttribute("fullevents", str(self.fulleventsv != 0))
        return
    pass

def GetAttrInt(attr, default):
    try:
        return int(attr.nodeValue)
    except Exception, e:
        _oi_logging.error("Error getting init parm " + attr.nodeName +
                          ": " + str(e))
        return default

def GetAttrBool(attr, default):
    if (attr.nodeValue.lower() == "true") or (attr.nodeValue == "1"):
        return True
    elif (attr.nodeValue.lower() == "false") or (attr.nodeValue == "0"):
        return False
    else:
        _oi_logging.error ("Error getting init parm " + attr.nodeName)
        pass
    return default

class _GUIRestore(_saveprefs.RestoreHandler):
    def __init__(self):
        _saveprefs.RestoreHandler.__init__(self, "guiparms")
        return

    def restore(self, node):
        global init_windowheight
        global init_windowwidth
        global init_sashposition
        global init_bsashposition
        global init_treenamewidth
        global init_fullevents
        global init_logevents
        
        for i in range(0, node.attributes.length):
            attr = node.attributes.item(i)
            if (attr.nodeName == "windowwidth"):
                init_windowwidth = GetAttrInt(attr, init_windowwidth)
            elif (attr.nodeName == "windowheight"):
                init_windowheight = GetAttrInt(attr, init_windowheight)
            elif (attr.nodeName == "sashposition"):
                init_sashposition = GetAttrInt(attr, init_sashposition)
            elif (attr.nodeName == "bsashposition"):
                init_sashposition = GetAttrInt(attr, init_bsashposition)
            elif (attr.nodeName == "treenamewidth"):
                init_treenamewidth = GetAttrInt(attr, init_treenamewidth)
            elif (attr.nodeName == "logevents"):
                init_logevents = GetAttrBool(attr, init_logevents)
            elif (attr.nodeName == "fullevents"):
                init_fullevents = GetAttrBool(attr, init_fullevents)
                pass
            pass
        return
    pass

_GUIRestore()
    
