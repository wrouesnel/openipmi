# gui_term.py
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

import Tix
import _term

def gpos(x, y):
    return str(y+1) + "." + str(x)
        
class Terminal(_term.TerminalEmulator):
    def __init__(self, parent):
        self.fsize = 8

        _term.TerminalEmulator.__init__(self)

        self.fonts = ("-family terminal -size " + str(self.fsize)
                      + " -weight normal -underline 0",
                      # Bold
                      "-family terminal -size " + str(self.fsize)
                      + " -weight bold -underline 0",
                      # Underline
                      "-family terminal -size " + str(self.fsize)
                      + " -weight normal -underline 1",
                      # Bold Underline
                      "-family terminal -size " + str(self.fsize)
                      + " -weight bold -underline 1")

        self.colors = ("black",
                       "red",
                       "green",
                       "yellow",
                       "blue",
                       "magenta",
                       "cyan",
                       "white")

        self.text = Tix.Text(parent, width=self.width, height=self.height,
                             state="normal", wrap="none", font=self.fonts[0])
        self.text.pack(side=Tix.TOP, fill=Tix.BOTH, expand=1)

        # We create a tag for every possible terminal configuration, based
        # upon an equation using the colors and font type.
        for f in range(0, len(self.fonts)):
            for fg in range(0, len(self.colors)):
                for bg in range(0, len(self.colors)):
                    idx = (f * 8 * 8) + (fg * 8) + bg;
                    self.text.tag_configure(str(idx), font=self.fonts[f],
                                            foreground=self.colors[fg],
                                            background=self.colors[bg])
                    pass
                pass
            pass

        self.default_tag = str(7 * 8) # white forground, black background

        for i in range(1, self.height+1):
            self.text.insert(str(i) + ".1", "%*s\n" % (self.width, ""),
                             self.default_tag)
            pass

        self.handle_cursor()

        self.text.bind("<Key>", self.HandleChar)
        self.text.bind("<Control-Key>", self.HandleControlChar)

        self.text.focus_set()
        return

    def DrawText(self, fg_color, bg_color, flags, x, y, val):
        if (flags & _term.INVERSE):
            tmp = bg_color
            bg_color = fg_color
            fg_color = tmp
            pass
        # FIXME - we don't handle blinking or concealed
        flags &= 3
        tag = str((flags * 8 * 8) + (fg_color * 8) + bg_color);
        self.text.delete(gpos(x, y), gpos(x+len(val), y))
        self.text.insert(gpos(x, y), val, tag)
        return

    def DrawCursor(self, fg_color, bg_color, flags, x, y, val):
        # Draw cursor as inverse, just flip the background and foreground
        self.DrawText(bg_color, fg_color, flags, x, y, val)
        return

    def ScrollLines(self, y1, y2):
        self.text.delete(gpos(0, y1), gpos(0, y1+1))
        if (y2 == self.height-1):
            self.text.insert("end", "\n%*s" % (self.width, ""),
                             self.default_tag)
            pass
        else:
            # Not (y2+1), because we deleted a line
            pos = gpos(0, y2)
            self.text.insert(pos, "%*s\n" % (self.width, ""),
                             self.default_tag)
            pass
        return
    
    def ScrollLinesUp(self, y1, y2):
        self.text.delete(gpos(0, y2), gpos(0, y2+1))
        if (y1 == self.height-1):
            self.text.insert("end", "\n%*s" % (self.width, ""),
                             self.default_tag)
            pass
        else:
            pos = gpos(0, y1)
            self.text.insert(pos, "%*s\n" % (self.width, ""),
                             self.default_tag)
            pass
        return

    def DeleteChars(self, x, y, len):
        pos = gpos(x, y)
        endpos = gpos(x+len, y)
        self.text.delete(pos, endpos)
        self.text.insert(str(y+1) + ".end", "%*s" % (len, ""),
                         self.default_tag)
        return
    
    def InsertChars(self, x, y, len):
        self.text.delete(gpos(self.width-len, y), gpos(self.width, y))
        self.text.insert(gpos(x, y), "%*s" % (len, ""),
                         self.default_tag)
        return
    
    def SendBack(self, data):
        self.HandleTerminalOutput(data)
        return

    def Bell(self):
        return

    def RequestSizeChange(self, w, h):
        return
    
    def HandleChar(self, event):
        key = event.keysym
        if (len(key) == 1):
            s = key
        elif (key == "Return") or (key == "KP_Enter"):
            s = "\x0d"
        elif (key == "Backspace"):
            s = "\x08"
        elif (key == "Up"):
            s = "\x1b[A"
        elif (key == "Down"):
            s = "\x1b[B"
        elif (key == "Right"):
            s = "\x1b[C"
        elif (key == "Left"):
            s = "\x1b[D"
        elif (key == "Next"):
            s = "\x1b[6~"
        elif (key == "Prior"):
            s = "\x1b[5~"
        elif (key == "Insert"):
            s = "\x1b[2~"
        elif (key == "Home"):
            s = "\x1b[OH"
        elif (key == "End"):
            s = "\x1b[OF"
        elif (key == "Delete"):
            s = "\x1b[3~"
        elif (key == "F1"):
            s = "\x1bOP"
        elif (key == "F2"):
            s = "\x1bOQ"
        elif (key == "F3"):
            s = "\x1bOR"
        elif (key == "F4"):
            s = "\x1bOS"
        elif (key == "F5"):
            s = "\x1b[15~"
        elif (key == "F6"):
            s = "\x1b[17~"
        elif (key == "F7"):
            s = "\x1b[18~"
        elif (key == "F8"):
            s = "\x1b[19~"
        elif (key == "F9"):
            s = "\x1b[20~"
        elif (key == "F10"):
            s = "\x1b[21~"
        elif (key == "F11"):
            s = "\x1b[23~"
        elif (key == "F12"):
            s = "\x1b[24~"
        elif (len(event.char) == 1) and (event.char < chr(255)):
            s = event.char

        # Keypad stuff comes after the check because if numlock is off, the
        # event.char will be empty
        elif (key == "KP_Add"):
            s = "\x1bOl"
        elif (key == "KP_Subtract"):
            s = "\x1bOm"
        elif (key == "KP_Delete"):
            s = "\x1bOn"
        elif (key == "KP_Multiply"):
            s = "\x1bOQ"
        elif (key == "KP_Divide"):
            s = "\x1bOR"
        elif (key == "KP_Insert"):
            s = "\x1bOp"
        elif (key == "KP_End"):
            s = "\x1bOq"
        elif (key == "KP_Down"):
            s = "\x1bOr"
        elif (key == "KP_Next"):
            s = "\x1bOs"
        elif (key == "KP_Left"):
            s = "\x1bOt"
        elif (key == "KP_Begin"):
            s = "\x1bOu"
        elif (key == "KP_Right"):
            s = "\x1bOv"
        elif (key == "KP_Home"):
            s = "\x1bOw"
        elif (key == "KP_Up"):
            s = "\x1bOx"
        elif (key == "KP_Prior"):
            s = "\x1bOy"
        else:
            return "break"
        self.HandleTerminalOutput(s)
        return "break"
    
    def HandleControlChar(self, event):
        key = event.keysym
        if (len(key) != 1):
            return
        if ((key >= 'A') and (key <= 'B')): # '@' 'A' .. 'Z'
            s = "%c" % (ord(key)-64)
            pass
        elif ((key >= 'a') and (key <= 'z')): # 'a' .. 'z'
            s = "%c" % (ord(key)-96)
        elif (key < ' '):
            s = key
            pass
        else:
            return "break"
        self.HandleTerminalOutput(s)
        return "break"
    
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

class MyApp(Tix.Tk):
    def __init__(self):
        Tix.Tk.__init__(self)
        term = TestTerm(self)
        return
    
    pass

if __name__ == "__main__":
    app = MyApp()
    app.mainloop()


