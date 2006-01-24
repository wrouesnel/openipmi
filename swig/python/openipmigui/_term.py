# _term.py
#
# openipmi GUI terminal handling for SoL
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
import wx.lib.colourdb

black = 0
red = 1
green = 2
yellow = 3
blue = 4
magenta = 5
cyan = 6
white = 7

BOLD = 1
UNDERLINE = 2
INVERSE = 4
BLINK = 8

class TerminalEmulator:
    def __init__(self):
        self.buf = [ ]
        # Style is (fg, bg, flags)
        for i in range(0, 24):
            self.buf.append([ ])
            for j in range(0, 80):
                self.buf[i].append(" ")
                pass
            pass
        self.x = 0
        self.y = 0
        self.height = 24
        self.width = 80
        return

    def check_scroll(self):
        redraw = False
        while (self.y >= self.height):
            redraw = True
            self.y -= 1
            del(self.buf[0])
            self.buf.append([ ])
            i = self.height-1
            for j in range(0, self.width):
                self.buf[i].append(" ")
                pass
            pass
        if (redraw):
            for i in range(0, self.height):
                s = ""
                for j in range(0, self.width):
                    s += self.buf[i][j]
                    pass
                self.DrawText(white, black, 0, 0, i, s)
                pass
            pass
        return

    def output_at(self, x, y, len):
        s = ""
        for i in range(0, len):
            s += self.buf[y][x+i]
            pass
        self.DrawText(white, black, 0, x, y, s)
        return

    def handle_cursor(self):
        if (self.x == self.width):
            self.DrawCursor(white, black, 0, self.x-1, self.y,
                            self.buf[self.y][self.x-1])
            pass
        else:
            self.DrawCursor(white, black, 0, self.x, self.y,
                            self.buf[self.y][self.x])
            pass
        return

    def restore_cursor(self):
        if (self.x == self.width):
            self.output_at(self.x-1, self.y, 1)
            pass
        else:
            self.output_at(self.x, self.y, 1)
            pass
        return
        
    def output_data(self, len):
        if (self.x == self.width):
            # Cursor is at the end of the line, redraw the char where
            # the cursor is sitting.
            self.restore_cursor()
            pass
        if (len == 0):
            return
        self.output_at(self.x, self.y, len)
        self.x += len
        self.handle_cursor()
        return

    def ProcessInput(self, data):
        pos = 0
        while (len(data) > 0):
            if (pos >= len(data)):
                self.output_data(pos)
                data = ""
                pass
            elif (data[pos] == '\n'):
                self.output_data(pos)
                self.restore_cursor()
                data = data[pos+1:]
                self.y += 1
                self.check_scroll()
                self.handle_cursor();
                pos = 0
                pass
            elif (data[pos] == '\r'):
                self.output_data(pos)
                self.restore_cursor()
                data = data[pos+1:]
                self.x = 0
                self.handle_cursor();
                pos = 0
                pass
            elif ((pos + self.x) >= self.width):
                self.output_data(pos)
                self.x = 0
                self.y += 1
                self.check_scroll()
                data = data[pos:]
                pos = 0
                pass
            else:
                self.buf[self.y][self.x+pos] = data[pos]
                pos += 1
                pass
            pass
        return

    def ResizeTerminal(self, w, h):
        return

    def Width(self):
        return self.width

    def Height(self):
        return self.height

    def Update(self):
        return

    def ExposeArea(self, x, y, w, h):
        for i in range(y, y+h):
            self.output_at(x, i, w)
            pass
        self.handle_cursor()
        return

    def Reset(self):
        return
    
    pass


class Terminal(TerminalEmulator):
    def __init__(self, parent):
        self.textctrl = wx.TextCtrl(parent, -1,
                                    style=(wx.TE_MULTILINE | wx.HSCROLL
                                           | wx.TE_READONLY))
        
        self.style = wx.TextAttr()

        self.fonts = (wx.Font(pointSize = 10,
                              family = wx.FONTFAMILY_TELETYPE,
                              style = wx.FONTSTYLE_NORMAL,
                              weight = wx.FONTWEIGHT_NORMAL,
                              underline = False,
                              faceName = "",
                              encoding = wx.FONTENCODING_ISO8859_1),
                      # Bold
                      wx.Font(pointSize = 10,
                              family = wx.FONTFAMILY_TELETYPE,
                              style = wx.FONTSTYLE_NORMAL,
                              weight = wx.FONTWEIGHT_BOLD,
                              underline = False,
                              faceName = "",
                              encoding = wx.FONTENCODING_ISO8859_1),
                      # Underline
                      wx.Font(pointSize = 10,
                              family = wx.FONTFAMILY_TELETYPE,
                              style = wx.FONTSTYLE_NORMAL,
                              weight = wx.FONTWEIGHT_NORMAL,
                              underline = True,
                              faceName = "",
                              encoding = wx.FONTENCODING_ISO8859_1),
                      # Bold Underline
                      wx.Font(pointSize = 10,
                              family = wx.FONTFAMILY_TELETYPE,
                              style = wx.FONTSTYLE_NORMAL,
                              weight = wx.FONTWEIGHT_BOLD,
                              underline = True,
                              faceName = "",
                              encoding = wx.FONTENCODING_ISO8859_1))

        self.colors = (wx.BLACK,
                       wx.RED,
                       wx.GREEN,
                       "Yellow",
                       wx.BLUE,
                       "Magenta",
                       wx.CYAN,
                       wx.WHITE)

        TerminalEmulator.__init__(self)

        for i in range(0, self.height-1):
            self.textctrl.AppendText("%*s\n" % (self.width, "") )
            pass
        self.textctrl.AppendText("%*s" % (self.width, "") )

        self.ExposeArea(0, 0, self.width, self.height)

        wx.EVT_CHAR(self.textctrl, self.HandleChar)
        return

    def DrawText(self, fg_color, bg_color, flags, x, y, val):
        pos = (y * (self.width+1)) + x
        if (flags & INVERSE):
            self.style.SetTextColour(self.colors[bg_color])
            self.style.SetBackgroundColour(self.colors[fg_color])
            pass
        else:
            self.style.SetTextColour(self.colors[fg_color])
            self.style.SetBackgroundColour(self.colors[bg_color])
            pass
        self.style.SetFont(self.fonts[flags & 3])
        # FIXME - we don't handle blinking
        self.textctrl.Replace(pos, pos+len(val), val)
        self.textctrl.SetStyle(pos, pos+len(val), self.style)
        return

    def DrawCursor(self, fg_color, bg_color, flags, x, y, val):
        # Draw cursor as inverse, just flip the background and foreground
        self.DrawText(bg_color, fg_color, flags, x, y, val)
        return
    
    def SendBack(self, data):
        self.HandleTerminalOutput(data)
        return

    def Bell(self):
        return

    def RequestSizeChange(self, w, h):
        return
    
    def HandleChar(self, event):
        key = event.GetKeyCode()
        if (event.ControlDown()):
            if ((key >= 64) and (key <= 90)): # '@' 'A' .. 'Z'
                s = "%c" % (key-64)
                pass
            if ((key >= 97) and (key <= 122)): # 'a' .. 'z'
                s = "%c" % (key-96)
            pass
        elif (key <= 255):
            s = "%c" % (key)
            pass
        else:
            return
        self.HandleTerminalOutput(s)
        return
    
    pass

#class MyApp(wx.App):
#    def __init__(self):
#        self.name = "app"
#        wx.App.__init__(self);
#
#    def OnInit(self):
#        frame = wx.Frame(None, -1)
#        term = Terminal(frame)
#        self.SetTopWindow(frame)
#        frame.Show(True)
#        return True
#
#app = MyApp()
#app.MainLoop()
