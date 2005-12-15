# _fru.py
#
# openipmi GUI handling for FRU data
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

import OpenIPMI
import _oi_logging
import wx
import wx.gizmos as gizmos

class FruInfoDisplay(wx.Dialog):
    def __init__(self, fru, name):
        self.fru = fru;
        wx.Dialog.__init__(self, None, -1, "FRU info for " + name,
                           size=wx.Size(400, 600),
                           style=wx.RESIZE_BORDER)

        sizer = wx.BoxSizer(wx.VERTICAL)

        tree = gizmos.TreeListCtrl(self)
        tree.AddColumn("Name")
        tree.AddColumn("Value")
        tree.SetMainColumn(0)
        tree.SetColumnWidth(0, 300)
        tree.SetColumnWidth(1, 100)
        
        sizer.Add(tree, 1, wx.GROW, 0)

        ok = wx.Button(self, -1, "Ok")
        self.Bind(wx.EVT_BUTTON, self.ok, ok);
        sizer.Add(ok, 0, wx.ALIGN_CENTRE | wx.ALL, 2)

        name_s = [ "" ]
        node_s = [ None ]
        rv = fru.get_root_node(name_s, node_s)
        if (rv != 0):
            _oi_logging.error("unable to get FRU node: " + str(rv))
            self.Destroy();
            return
        treeroot = tree.AddRoot(name_s[0])
        self.add_fru_data(tree, treeroot, node_s[0])

        self.SetSizer(sizer)
        self.Bind(wx.EVT_CLOSE, self.OnClose)
        self.CenterOnScreen();
        self.Show(True)

    def ok(self, event):
        self.Close()

    def OnClose(self, event):
        self.Destroy()

    def add_fru_data(self, tree, item, node):
        i = 0
        while True:
            name_s = [ "" ]
            type_s = [ "" ]
            value_s = [ "" ]
            node_s = [ None ]
            rv = node.get_field(i, name_s, type_s, value_s, node_s)
            if (rv == OpenIPMI.einval):
                return
            if (rv == 0):
                # Ignore other errors, just keep going
                if (type_s[0] == "subnode"):
                    sub = tree.AppendItem(item, name_s[0])
                    self.add_fru_data(tree, sub, node_s[0])
                elif (name_s[0] == None):
                    sub = tree.AppendItem(item, str(i))
                    tree.SetItemText(sub, value_s[0], 1)
                else:
                    sub = tree.AppendItem(item, name_s[0])
                    tree.SetItemText(sub, value_s[0], 1)
                    pass
                pass
            i = i + 1
