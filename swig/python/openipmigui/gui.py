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
import wx
import _domainDialog

class IPMITreeDummyItem:
    def __init__(self):
        pass

class IPMITreeCtrl(wx.TreeCtrl):
    def __init__(self, parent):
        wx.TreeCtrl.__init__(self, parent)

    def OnCompareItems(self, item1, item2):
        t1 = self.GetItemText(item1)
        t2 = self.GetItemText(item2)
        self.log.WriteText('compare: ' + t1 + ' <> ' + t2 + '\n')
        if t1 < t2: return -1
        if t1 == t2: return 0
        return 1

class IPMICloser:
    def __init__(self, ui, count):
        self.ui = ui
        self.count = count
    
    def domain_cb(self, domain):
        domain.close(self)

    def domain_close_done_cb(self):
        self.count = self.count - 1
        if (self.count == 0):
            self.ui.Close(True)

class IPMIGUI_Timer(wx.Timer):
    def __init__(self, ui):
        wx.Timer.__init__(self)
        self.ui = ui
        self.Start(1000, oneShot=True)

    def Notify(self):
        self.ui.Timeout()
        self.Start(1000, oneShot=True)

class IPMIGUI(wx.Frame):
    def __init__(self, mainhandler):
        wx.Frame.__init__(self, None, 01, "IPMI GUI")

        self.mainhandler = mainhandler
        
        menubar = wx.MenuBar()
        
        filemenu = wx.Menu()
        filemenu.Append(wx.ID_EXIT, "E&xit\tCtrl-Q", "Exit")
        self.Bind(wx.EVT_MENU, self.quit, id=wx.ID_EXIT);
        item = filemenu.Append(-1, "&Open Domain\tCtrl-O", "Open Domain")
        self.Bind(wx.EVT_MENU, self.openDomain, item);
        item = filemenu.Append(-1, "&Save Prefs\tCtrl-S", "Save Prefs")
        self.Bind(wx.EVT_MENU, self.savePrefs, item);
        menubar.Append(filemenu, "&File")
        
        viewmenu = wx.Menu()
        item = viewmenu.Append(-1, "&Expand All\tCtrl-E", "Expand All")
        self.Bind(wx.EVT_MENU, self.ExpandAll, item);
        item = viewmenu.Append(-1, "&Collapse All\tCtrl-C", "Collapse All")
        self.Bind(wx.EVT_MENU, self.CollapseAll, item);
        menubar.Append(viewmenu, "&View")

        self.SetMenuBar(menubar)

        box = wx.BoxSizer(wx.HORIZONTAL)

        isz = (16, 16)
        self.tree = IPMITreeCtrl(self)
        self.treeroot = self.tree.AddRoot("Domains")
        self.tree.SetPyData(self.treeroot, self)
        self.setup_item(self.treeroot, active=True)
        box.Add(self.tree, 1,
                wx.ALIGN_LEFT | wx.ALIGN_TOP | wx.ALIGN_BOTTOM | wx.GROW,
                0)

        self.logwindow = wx.TextCtrl(self, -1,
                                     style=(wx.TE_MULTILINE
                                            | wx.TE_READONLY
                                            | wx.HSCROLL))
        box.Add(self.logwindow, 1,
                wx.ALIGN_RIGHT | wx.ALIGN_TOP | wx.ALIGN_BOTTOM | wx.GROW,
                0)
        self.logcount = 0
        self.maxloglines = 1000

        self.SetSizer(box);

        self.tree.Bind(wx.EVT_TREE_ITEM_RIGHT_CLICK, self.TreeMenu)
        self.tree.Bind(wx.EVT_TREE_ITEM_EXPANDED, self.TreeExpanded)

        self.Show(True)

        self.last_scan = None
        self.timer = IPMIGUI_Timer(self)

    def Timeout(self):
        if self.last_scan != None:
            next = self.last_scan
        else:
            next = self.tree.GetFirstVisibleItem()
        callcount = 0
        checkcount = 0
        while (callcount < 100) and (checkcount < 1000) and next.IsOk():
            data = self.tree.GetPyData(next)
            if (data != None) and (hasattr(data, "DoUpdate")):
                callcount = callcount + 1
                data.DoUpdate()
            next = self.tree.GetNextVisible(next)
            checkcount = checkcount + 1
            
        if next.IsOk():
            self.last_scan = next
        else:
            self.last_scan = None
        
    def quit(self, event):
        self.closecount = len(self.mainhandler.domains)
        if (self.closecount == 0):
            self.Close(True)
            return
        closer = IPMICloser(self, self.closecount)
        for v in self.mainhandler.domains.itervalues():
            v.domain_id.convert_to_domain(closer)

    def openDomain(self, event):
        dialog = _domainDialog.OpenDomainDialog(self.mainhandler)
        dialog.CenterOnScreen();
        dialog.Show(True);

    def savePrefs(self, event):
        self.mainhandler.savePrefs()

    def ExpandItem(self, item):
        (child, cookie) = self.tree.GetFirstChild(item)
        while child.IsOk():
            if self.tree.ItemHasChildren(child):
                self.tree.Expand(child)
                self.ExpandItem(child)
            (child, cookie) = self.tree.GetNextChild(item, cookie)
        
    def ExpandAll(self, event):
        self.tree.Expand(self.treeroot)
        self.ExpandItem(self.treeroot)
        
    def CollapseItem(self, item):
        (child, cookie) = self.tree.GetFirstChild(item)
        while child.IsOk():
            if self.tree.ItemHasChildren(child):
                self.tree.Collapse(child)
                self.CollapseItem(child)
            (child, cookie) = self.tree.GetNextChild(item, cookie)
        
    def CollapseAll(self, event):
        self.CollapseItem(self.treeroot)
        
    def new_log(self, log):
        newlines = log.count('\n') + 1
        self.logwindow.AppendText(log + "\n")
        self.logcount += newlines
        while (self.logcount > self.maxloglines):
            end = self.logwindow.GetLineLength(0)
            self.logwindow.Remove(0, end+1)
            self.logcount -= 1

    def setup_item(self, item, active=False):
        data = self.tree.GetPyData(item)
        data.active = active
        data.num_warning = 0
        data.num_severe = 0
        data.num_critical = 0
        if (not active):
            self.tree.SetItemTextColour(item, wx.LIGHT_GREY)

    def cleanup_item(self, item):
        data = self.tree.GetPyData(item)
        if (data == None):
            return;
        parent = self.tree.GetItemParent(item)
        if not parent.IsOk():
            return
        while (data.num_warning > 0):
            data.num_warn = data.num_warn - 1;
            self.decr_item_warning(parent); 
        while (data.num_severe > 0):
            data.num_severe = data.num_severe - 1;
            self.decr_item_severe(parent); 
        while (data.num_critical > 0):
            data.num_critical = data.num_critical - 1;
            self.decr_item_critical(parent); 

    def add_domain(self, d):
        d.name_str = str(d)
        d.treeroot = self.tree.AppendItem(self.treeroot, d.name_str)
        self.tree.SetPyData(d.treeroot, d)
        self.setup_item(d.treeroot)
        d.entityroot = self.tree.AppendItem(d.treeroot, "Entities")
        self.tree.SetPyData(d.entityroot, IPMITreeDummyItem())
        self.setup_item(d.entityroot, active=True)
        d.mcroot = self.tree.AppendItem(d.treeroot, "MCs")
        self.tree.SetPyData(d.mcroot, IPMITreeDummyItem())
        self.setup_item(d.mcroot, active=True)
        self.tree.Expand(self.treeroot)

    def prepend_item(self, o, name, value, data=None, parent=None):
        if (data == None):
            data = IPMITreeDummyItem()
        data.name_str = name
        if (parent == None):
            parent = o.treeroot
        if (value == None):
            item = self.tree.PrependItem(parent, name + ":")
            self.tree.SetItemTextColour(item, wx.LIGHT_GREY)
        else:
            item = self.tree.PrependItem(parent, name + ":\t" + value)
            self.tree.SetItemTextColour(item, wx.BLACK)
        self.tree.SetPyData(item, data)
        return item

    def append_item(self, o, name, value, data=None, parent=None):
        if (data == None):
            data = IPMITreeDummyItem()
        data.name_str = name
        if (parent == None):
            parent = o.treeroot
        if (value == None):
            item = self.tree.AppendItem(parent, name + ":")
            self.tree.SetItemTextColour(item, wx.LIGHT_GREY)
        else:
            item = self.tree.AppendItem(parent, name + ":\t" + value)
            self.tree.SetItemTextColour(item, wx.BLACK)
        self.tree.SetPyData(item, data)
        return item

    def set_item_text(self, item, value):
        data = self.tree.GetPyData(item)
        name = data.name_str
        if (value == None):
            self.tree.SetItemText(item, name + ":")
            self.tree.SetItemTextColour(item, wx.LIGHT_GREY)
        else:
            self.tree.SetItemText(item, name + ":\t" + value)
            if (hasattr(data, "active")):
                if (data.active):
                    self.tree.SetItemTextColour(item, wx.BLACK)
            else:
                self.tree.SetItemTextColour(item, wx.BLACK)

    def set_item_inactive(self, item):
        data = self.tree.GetPyData(item)
        data.active = False
        self.tree.SetItemTextColour(item, wx.LIGHT_GREY)
        
    def set_item_active(self, item):
        data = self.tree.GetPyData(item)
        data.active = True
        if (data.num_critical > 0):
            self.tree.SetItemTextColour(item, wx.BLUE)
            return
        if (data.num_severe > 0):
            self.tree.SetItemTextColour(item, wx.RED)
            return
        if (data.num_warning > 0):
            self.tree.SetItemTextColour(item, wx.NamedColour('YELLOW'))
            return
        self.tree.SetItemTextColour(item, wx.BLACK)
        
    def incr_item_warning(self, item):
        parent = self.tree.GetItemParent(item)
        if parent.IsOk():
           self.incr_item_warning(parent); 
        data = self.tree.GetPyData(item)
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
            self.tree.SetItemTextColour(item, wx.NamedColour('YELLOW'))
        
    def decr_item_warning(self, item):
        parent = self.tree.GetItemParent(item)
        if parent.IsOk():
           self.decr_item_warning(parent); 
        data = self.tree.GetPyData(item)
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
        self.tree.SetItemTextColour(item, wx.BLACK)
        
    def incr_item_severe(self, item):
        parent = self.tree.GetItemParent(item)
        if parent.IsOk():
           self.incr_item_severe(parent); 
        data = self.tree.GetPyData(item)
        if (data == None):
            return
        data.num_severe = data.num_severe + 1
        if (not data.active):
            return
        if (data.num_critical > 0):
            return
        if (data.num_severe == 1):
            self.tree.SetItemTextColour(item, wx.RED)
        
    def decr_item_severe(self, item):
        parent = self.tree.GetItemParent(item)
        if parent.IsOk():
           self.decr_item_severe(parent); 
        data = self.tree.GetPyData(item)
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
            self.tree.SetItemTextColour(item, wx.NamedColour('YELLOW'))
            return
        self.tree.SetItemTextColour(item, wx.BLACK)
        
    def incr_item_critical(self, item):
        parent = self.tree.GetItemParent(item)
        if parent.IsOk():
           self.incr_item_critical(parent); 
        data = self.tree.GetPyData(item)
        if (data == None):
            return
        data.num_critical = data.num_critical + 1
        if (not data.active):
            return
        if (data.num_critical == 1):
            self.tree.SetItemTextColour(item, wx.BLUE)
        
    def decr_item_critical(self, item):
        parent = self.tree.GetItemParent(item)
        if parent.IsOk():
           self.decr_item_critical(parent); 
        data = self.tree.GetPyData(item)
        if (data == None):
            return
        data.num_critical = data.num_critical - 1
        if (not data.active):
            return
        if (data.num_critical > 0):
            return
        if (data.num_severe > 0):
            self.tree.SetItemTextColour(item, wx.RED)
            return
        if (data.num_warning > 0):
            self.tree.SetItemTextColour(item, wx.NamedColour('YELLOW'))
            return
        self.tree.SetItemTextColour(item, wx.BLACK)
        
    def get_item_pos(self, item):
        rect = self.tree.GetBoundingRect(item)
        if (rect == None):
            return None
        return wx.Point(rect.GetLeft(), rect.GetBottom())

    def TreeMenu(self, event):
        item = event.GetItem()
        data = self.tree.GetPyData(item)
        if (data != None) and (hasattr(data, "HandleMenu")):
            data.HandleMenu(event)

    # FIXME - expand of parent doesn't affect children...
    def TreeExpanded(self, event):
        item = event.GetItem()
        data = self.tree.GetPyData(item)
        if (data != None) and (hasattr(data, "HandleExpand")):
            data.HandleExpand(event)

    def remove_domain(self, d):
        if (hasattr(d, "treeroot")):
            self.tree.Delete(d.treeroot)
            self.cleanup_item(d.treeroot)

    def add_entity(self, d, e, parent=None):
        if (parent == None):
            parent = d.entityroot
        else:
            parent = parent.treeroot
        e.name_str = str(e)
        e.treeroot = self.tree.AppendItem(parent, e.name_str)
        self.tree.SetPyData(e.treeroot, e)
        self.setup_item(e.treeroot)
        e.sensorroot = self.tree.AppendItem(e.treeroot, "Sensors")
        self.tree.SetPyData(e.sensorroot, IPMITreeDummyItem())
        self.setup_item(e.sensorroot, active=True)
        e.controlroot = self.tree.AppendItem(e.treeroot, "Controls")
        self.tree.SetPyData(e.controlroot, IPMITreeDummyItem())
        self.setup_item(e.controlroot, active=True)
    
    def remove_entity(self, e):
        if (hasattr(e, "treeroot")):
            self.tree.Delete(e.treeroot)
            self.cleanup_item(e.treeroot)

    def add_mc(self, d, m):
        m.name_str = str(m)
        m.treeroot = self.tree.AppendItem(d.mcroot, m.name_str)
        self.tree.SetPyData(m.treeroot, m)
        self.setup_item(m.treeroot)

    def remove_mc(self, m):
        if (hasattr(m, "treeroot")):
            self.tree.Delete(m.treeroot)
            self.cleanup_item(m.treeroot)

    def add_sensor(self, e, s):
        s.name_str = str(s)
        s.treeroot = self.tree.AppendItem(e.sensorroot, s.name_str)
        self.tree.SetPyData(s.treeroot, s)
        self.setup_item(s.treeroot, active=True)

    def remove_sensor(self, s):
        if (hasattr(s, "treeroot")):
            self.tree.Delete(s.treeroot)
            self.cleanup_item(s.treeroot)

    def add_control(self, e, c):
        c.name_str = str(c)
        c.treeroot = self.tree.AppendItem(e.controlroot, c.name_str)
        self.tree.SetPyData(c.treeroot, c)
        self.setup_item(c.treeroot, active=True)

    def remove_control(self, c):
        if (hasattr(c, "treeroot")):
            self.tree.Delete(c.treeroot)
            self.cleanup_item(c.treeroot)
