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

id_st = 1200

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
        self.InputHandler = self.Input0
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
            self.ScrollLines(0, self.height-1)
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
        
    def output_str(self, s):
        if (len(s) == 0):
            return
        do_scroll = False
        if (self.x == self.width):
            # Cursor is at the end of the line, redraw the char where
            # the cursor is sitting.
            self.restore_cursor()
            self.x = 0;
            self.y += 1;
            self.check_scroll()
            pass
        while ((self.x + len(s)) >= self.width):
            # The string exceeds the line length, do it in pieces
            outlen = self.width - self.x
            do_scroll = True
            self.buf[self.y][self.x:self.x+outlen] = s[0:outlen]
            self.output_at(self.x, self.y, outlen)
            self.x = 0;
            self.y += 1;
            s = s[outlen:]
            self.check_scroll()
            pass
        outlen = len(s)
        self.buf[self.y][self.x:self.x+outlen] = s[0:outlen]
        self.output_at(self.x, self.y, outlen)
        self.x += outlen
        self.handle_cursor()
        return

    # After '\e['
    def Input2(self, c, s):
        if (c == 'A'): # Up
            if (self.y > 0):
                self.restore_cursor()
                self.y -= 1
                self.handle_cursor();
                pass
            pass
        elif (c == 'B'): # Down
            if (self.y < (self.height-1)):
                self.restore_cursor()
                self.y += 1
                self.handle_cursor();
                pass
            pass
        elif (c == 'C'): # Right
            if (self.x < (self.width-1)):
                self.restore_cursor()
                self.x += 1
                self.handle_cursor();
                pass
            pass
        elif (c == 'D'): # Right
            if (self.x > 0):
                self.restore_cursor()
                self.x -= 1
                self.handle_cursor();
                pass
            pass
        elif ((c >= '0') and (c <= '9')):
            if (self.parms == None):
                self.parms = [ int(c) ]
            else:
                currparm = len(self.parms) - 1
                self.parms[currparm] *= 10
                self.parms[currparm] += int(c)
                pass
            return "" # Stay in Input2
        elif (c == ';'): # Right
            if (self.parms == None):
                self.parms = [ 0, 0 ]
            else:
                self.parms.append(0)
                pass
            return "" # Stay in Input2
        elif (c == 'H'): # Move to position specified by self.parms
            if (self.parms == None):
                x = 1
                y = 1
                pass
            elif (len(self.parms) == 1):
                y = self.parms[0]
                x = 1
                pass
            else:
                y = self.parms[0]
                x = self.parms[1]
                pass
            if (x < 1):
                x = 1
            elif (x > self.width):
                x = self.width
                pass
            self.restore_cursor()
            self.x = x - 1
            self.y = y - 1
            self.handle_cursor();
            pass
        self.InputHandler = self.Input0
        return ""

    # After an escape
    def Input1(self, c, s):
        if (c == '['):
            self.parms = None
            self.InputHandler = self.Input2
            pass
        else:
            self.InputHandler = self.Input0
            pass
        return ""

    # "normal" input mode
    def Input0(self, c, s):
        if ((c >= ' ') and (c <= '~')):
            return s + c
        else:
            if (c == '\n'):
                self.restore_cursor()
                self.y += 1
                self.check_scroll()
                self.handle_cursor();
                pass
            elif (c == '\r'):
                self.restore_cursor()
                self.x = 0
                self.handle_cursor();
                pass
            elif (c == '\t'):
                self.restore_cursor()
                if (self.x >= self.width-8):
                    self.x = self.width-1
                else:
                    self.x = ((self.x / 8) * 8) + 8
                    pass
                self.handle_cursor();
                pass
            elif (c == '\007'): #bell
                self.Bell()
            elif (c == '\010'): #backspace
                if (self.x > 0):
                    self.restore_cursor()
                    self.x -= 1
                    self.handle_cursor();
                    pass
                pass
            elif (c == '\x1b'):
                self.InputHandler = self.Input1
                pass
            pass
        return ""
    
    def ProcessInput(self, data):
        s = ""
        for c in data:
            s = self.InputHandler(c, s)
            pass
        self.output_str(s)
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
        self.style = wx.TextAttr()

        self.fsize = 8

        self.fonts = (wx.Font(pointSize = self.fsize,
                              family = wx.FONTFAMILY_TELETYPE,
                              style = wx.FONTSTYLE_NORMAL,
                              weight = wx.FONTWEIGHT_NORMAL,
                              underline = False,
                              faceName = "",
                              encoding = wx.FONTENCODING_ISO8859_1),
                      # Bold
                      wx.Font(pointSize = self.fsize,
                              family = wx.FONTFAMILY_TELETYPE,
                              style = wx.FONTSTYLE_NORMAL,
                              weight = wx.FONTWEIGHT_BOLD,
                              underline = False,
                              faceName = "",
                              encoding = wx.FONTENCODING_ISO8859_1),
                      # Underline
                      wx.Font(pointSize = self.fsize,
                              family = wx.FONTFAMILY_TELETYPE,
                              style = wx.FONTSTYLE_NORMAL,
                              weight = wx.FONTWEIGHT_NORMAL,
                              underline = True,
                              faceName = "",
                              encoding = wx.FONTENCODING_ISO8859_1),
                      # Bold Underline
                      wx.Font(pointSize = self.fsize,
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

        self.textctrl = wx.TextCtrl(parent, -1,
                                    style=(wx.TE_MULTILINE | wx.HSCROLL
                                           | wx.TE_READONLY))

        (self.charwidth, self.charheight,
         descent, eleading) = self.textctrl.GetFullTextExtent(" ",
                                                              self.fonts[0])
        
        TerminalEmulator.__init__(self)

        self.xpixels = self.charwidth * self.width
        self.ypixels = self.charheight * self.height

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

    def ScrollLines(self, y1, y2):
        self.textctrl.Remove(y1 * (self.width+1), (y1+1) * (self.width+1))
        if (y2 == self.height-1):
            self.textctrl.AppendText("\n%*s" % (self.width, "") )
            pass
        else:
            pos = (y2+1) * (self.width+1)
            self.textctrl.Replace(pos, pos, "%*s\n" % (self.width, "") )
            pass
        self.ExposeArea(0, y2, self.width, 1)
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
        if (key <= 255):
            s = "%c" % (key)
            pass
        elif (key == wx.WXK_UP):
            s = "\x1b[A"
        elif (key == wx.WXK_DOWN):
            s = "\x1b[B"
        elif (key == wx.WXK_RIGHT):
            s = "\x1b[C"
        elif (key == wx.WXK_LEFT):
            s = "\x1b[D"
        else:
            return
        self.HandleTerminalOutput(s)
        return
    
    pass

import sys
class TestTerm(Terminal):
    def __init__(self, parent):
        Terminal.__init__(self, parent)
        return

    def HandleTerminalOutput(self, s):
        # FIXME: hacks to remove
        sys.stdout.write(s)
        sys.stdout.flush()
        if (s[0] == '\x01'):
            self.ProcessInput("abcdefghijk")
            return
        self.ProcessInput(s)
        return
    pass

class MyApp(wx.App):
    def __init__(self):
        self.name = "app"
        wx.App.__init__(self);

    def OnInit(self):
        frame = wx.Frame(None, -1)
        term = TestTerm(frame)
        frame.SetSizeWH(term.xpixels+30, term.ypixels+30)
        self.SetTopWindow(frame)
        frame.Show(True)
        return True

if __name__ == "__main__":
    app = MyApp()
    app.MainLoop()


