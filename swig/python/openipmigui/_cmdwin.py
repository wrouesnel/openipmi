# _cmdwin.py
#
# openipmi GUI command window handling
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

import wx
import OpenIPMI

class CommandWindow(wx.TextCtrl):
    def __init__(self, parent):
        wx.TextCtrl.__init__(self, parent, -1,
                             style=(wx.TE_MULTILINE
                                    | wx.HSCROLL))
        self.currow = 0
        self.max_lines = 1000
        self.max_history = 100
        wx.EVT_CHAR(self, self.HandleChar)
        self.AppendText("> ")
        self.history = [ "" ]
        self.lasthist = 0
        self.currhist = 0

        self.cmdlang = OpenIPMI.alloc_cmdlang(self)
        self.indent = 0;
        self.cmd_in_progress = False
        return

    def cmdlang_down(self, cmdlang):
        self.indent += 2
        return
    
    def cmdlang_up(self, cmdlang):
        if (self.indent >= 2):
            self.indent -= 2
            pass
        return
    
    def HandleNewLines(self):
        while (self.GetNumberOfLines() > self.max_lines):
            self.Remove(0, self.GetLineLength(0)+1)
            self.currow -= 1
            pass
        return

    def InsertString(self, str):
        (colpos, rowpos) = self.PositionToXY(self.GetInsertionPoint())
        fixup = rowpos == self.currow
        inspos = self.XYToPosition(0, self.currow)
        self.Replace(inspos, inspos, str)
        (dummy, self.currow) = self.PositionToXY(self.GetLastPosition())
        if (fixup):
            self.SetInsertionPoint(self.XYToPosition(colpos, self.currow))
            pass
        else:
            self.SetInsertionPoint(self.XYToPosition(colpos, rowpos))
            pass
        self.HandleNewLines()
        self.ShowPosition(self.GetInsertionPoint())
        return
    
    def cmdlang_done(self, cmdlang):
        err = cmdlang.get_err()
        if (err != 0):
            errtext = cmdlang.get_errstr()
            objstr = cmdlang.get_objstr()
            location = cmdlang.get_location()
            if (location == None):
                location = ""
                pass
            if (objstr == ""):
                str = ("error: %s: %s (0x%x, %s)\n"
                       % (location, errtext, err,
                          OpenIPMI.get_error_string(err)))
                pass
            else:
                str = ("error: %s %s: %s (0x%x, %s)\n"
                       % (location, objstr, errtext, err,
                          OpenIPMI.get_error_string(err)))
                pass
            self.InsertString(str)
            pass
        self.cmd_in_progress = False
        self.AppendText("> ")
        return

    def cmdlang_out(self, cmdlang, name, value):
        if (cmdlang.is_help()):
            self.InsertString("%*s%s %s\n" % (self.indent, "", name, value))
            pass
        else:
            self.InsertString("%*s%s: %s\n" % (self.indent, "", name, value))
            pass
        return
    
    def cmdlang_out_binary(self, cmdlang, name, value):
        self.InsertString("%*s%s: %s\n" % (self.indent, "", name, str(value)))
        return
    
    def cmdlang_out_unicode(self, cmdlang, name, value):
        self.InsertString("%*s%s:U: %s\n" % (self.indent, "", name, str(value)))
        return
    
    def HandleNewHistory(self):
        self.history.append("")
        if (self.lasthist >= self.max_history):
            del self.history[0]
            pass
        else:
            self.lasthist += 1
            pass
        return
    
    def HandleChar(self, event):
        key = event.GetKeyCode()
        if ((key >= wx.WXK_SPACE) and (key < wx.WXK_DELETE)):
            # A key that will result in text addition.  Make sure it
            # only occurs on the last line and not in the prompt area.
            if (self.cmd_in_progress):
                return
            (col, row) = self.PositionToXY(self.GetInsertionPoint())
            if ((row != self.currow) or (col < 2)):
                # Ignore the keypress
                return
            event.Skip()
            pass
        elif ((key == wx.WXK_BACK) or (key == wx.WXK_DELETE)):
            # A key that will result in a backspace.  Make sure it
            # only occurs on the last line and not in the prompt area.
            if (self.cmd_in_progress):
                return
            (col, row) = self.PositionToXY(self.GetInsertionPoint())
            if ((row != self.currow) or (col <= 2)):
                # Ignore the keypress
                return
            event.Skip()
            pass
        elif (key == wx.WXK_RETURN):
            # Enter the command...
            if (self.cmd_in_progress):
                return
            self.SetInsertionPointEnd()
            command = self.GetLineText(self.currow)[2:]
            self.currow += 1;
            self.HandleNewLines();
            if (command != ""):
                self.AppendText("\n")
                self.history[self.lasthist] = command
                self.HandleNewHistory()
                self.cmdlang.handle(str(command))
                pass
            else:
                self.AppendText("\n> ")
                pass
            self.currhist = self.lasthist
            self.ShowPosition(self.GetInsertionPoint())
            pass
        elif (key == wx.WXK_UP):
            # Previous history
            if (self.cmd_in_progress):
                return
            if (self.currhist == 0):
                return
            if (self.currhist == self.lasthist):
                command = self.GetLineText(self.currow)[2:]
                self.history[self.lasthist] = command
                pass
            pos = self.XYToPosition(2, self.currow)
            self.Remove(pos, self.GetLastPosition())
            self.currhist -= 1
            self.AppendText(self.history[self.currhist])
            pass
        elif (key == wx.WXK_DOWN):
            if (self.cmd_in_progress):
                return
            # Next history
            if (self.currhist == self.lasthist):
                return
            pos = self.XYToPosition(2, self.currow)
            self.Remove(pos, self.GetLastPosition())
            self.currhist += 1
            self.AppendText(self.history[self.currhist])
            pass
        else:
            event.Skip()
            pass
        return

    pass
