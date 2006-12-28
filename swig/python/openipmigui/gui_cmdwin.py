# gui_cmdwin.py
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

import Tix
import xml.dom
import xml.dom.minidom
import OpenIPMI
import _saveprefs
import _misc
import os
import stat
import sys

init_history = [ ]

class CommandWindow(Tix.ScrolledText):
    def __init__(self, parent, ui):
        global init_history
        Tix.ScrolledText.__init__(self, parent)
        self.ui = ui
        self.currow = 0
        self.max_lines = 1000
        self.max_history = 100
        self.text.bind("<Key>", self.HandleChar)
        self.text.bind("<Control-Key>", self.HandleCtrlChar)
        self.text.insert("end", "> ")
        self.history = [ ]
        self.lasthist = 0
        for cmd in init_history:
            self.history.append(cmd[1])
            self.lasthist += 1
            pass
        self.history.append("")
        init_history = None
        self.currhist = self.lasthist

        self.cmdlang = OpenIPMI.alloc_cmdlang(self)
        self.indent = 0;
        self.cmd_in_progress = False

        self.bind("<Destroy>", self.OnDestroy)

        OpenIPMI.set_cmdlang_global_err_handler(self)
        return

    def global_cmdlang_err(self, objstr, location, errstr, errval):
        log = "Global cmdlang err: " + errstr;
        if (len(location) > 0) or (len(objstr) > 0):
            log += " at " + objstr + "(" + location + ")"
            pass
        log += ": " + errstr + " (" + str(errval) + ")"
        self.ui.new_log(log)
        return
    
    def OnDestroy(self, event):
        self.cmdlang = None
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
        lastline = int(self.text.index("end").split(".")[0]) - 1
        while (lastline > self.max_lines):
            self.text.delete("1.0", "2.0")
            lastline = int(self.text.index("end").split(".")[0]) - 1
            pass
        return

    def InsertString(self, string):
        (lastrow, lastcol) = self.text.index("end").split(".")
        lastrow = str(int(lastrow)-1)
        self.text.insert(lastrow + ".0", string)
        self.HandleNewLines()
        self.text.see("insert")
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
        self.text.insert("end", "> ")
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
        self.InsertString("%*s%s: %s\n" % (self.indent, "", name,
                                           _misc.HexArrayToStr(value)))
        return
    
    def cmdlang_out_unicode(self, cmdlang, name, value):
        self.InsertString("%*s%s:U: %s\n" % (self.indent, "", name,
                                             _misc.HexArrayToStr(value)))
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
    
    def HandleCtrlChar(self, event):
        # This is here to catch the control characters and pass them
        # on so HandleChar() doesn't trap and throw them away.
        return
    
    def HandleChar(self, event):
        key = event.keysym
        if (key == "BackSpace"):
            # A key that will result in a backspace.  Make sure it
            # only occurs on the last line and not in the prompt area.
            if (self.cmd_in_progress):
                return "break"
            (lastrow, lastcol) = self.text.index("end").split(".")
            lastrow = str(int(lastrow)-1)
            (currrow, currcol) = self.text.index("insert").split(".")
            if ((lastrow != currrow) or (int(currcol) <= 2)):
                # Ignore the keypress
                return "break"
            pass
        elif (key == "Delete"):
            # A key that will result in a deletion.  Make sure it
            # only occurs on the last line and not in the prompt area.
            if (self.cmd_in_progress):
                return "break"
            (lastrow, lastcol) = self.text.index("end").split(".")
            lastrow = str(int(lastrow)-1)
            (currrow, currcol) = self.text.index("insert").split(".")
            if ((lastrow != currrow) or (int(currcol) <= 1)):
                # Ignore the keypress
                return "break"
            pass
        elif (key == "Return"):
            # Enter the command...
            if (self.cmd_in_progress):
                return "break"
            (lastrow, lastcol) = self.text.index("end").split(".")
            lastrow = str(int(lastrow)-1)
            (currrow, currcol) = self.text.index("insert").split(".")
            if ((lastrow != currrow) or (int(currcol) <= 2)):
                # Ignore the keypress
                return "break"

            command = self.text.get(lastrow + ".2", lastrow + ".end")
            self.HandleNewLines();
            if (command != ""):
                self.text.insert("end", "\n")
                self.history[self.lasthist] = command
                self.HandleNewHistory()
                self.cmdlang.handle(str(command))
                pass
            else:
                self.text.insert("end", "\n> ")
                pass
            self.text.mark_set("insert", "end")
            self.currhist = self.lasthist
            self.text.see("insert")
            return "break"
        elif (key == "Up"):
            # Previous history
            if (self.cmd_in_progress):
                return "break"
            if (self.currhist == 0):
                return "break"
            (lastrow, lastcol) = self.text.index("end").split(".")
            lastrow = str(int(lastrow)-1)
            if (self.currhist == self.lasthist):
                command = self.text.get(lastrow + ".2", lastrow + ".end")
                self.history[self.lasthist] = command
                pass
            self.text.delete(lastrow + ".2", lastrow + ".end")
            self.currhist -= 1
            self.text.insert(lastrow + ".2", self.history[self.currhist])
            return "break"
        elif (key == "Down"):
            if (self.cmd_in_progress):
                return "break"
            # Next history
            if (self.currhist == self.lasthist):
                return "break"
            (lastrow, lastcol) = self.text.index("end").split(".")
            lastrow = str(int(lastrow)-1)
            self.text.delete(lastrow + ".2", lastrow + ".end")
            self.currhist += 1
            self.text.insert(lastrow + ".2", self.history[self.currhist])
            return "break"
        elif (len(event.char) == 1) and (event.char < chr(255)):
            # A key that will result in text addition.  Make sure it
            # only occurs on the last line and not in the prompt area.
            if (self.cmd_in_progress):
                return "break"
            (lastrow, lastcol) = self.text.index("end").split(".")
            lastrow = str(int(lastrow)-1)
            (currrow, currcol) = self.text.index("insert").split(".")
            if ((lastrow != currrow) or (int(currcol) < 2)):
                # Ignore the keypress
                return "break"
            pass
        elif ((key == "Left") or (key == "Right") or
              (key == "Insert") or
              (key == "End") or (key == "Home") or
              (key == "Prior") or (key == "Next")):
            # Pass these through
            return
        else:
            return "break"
        return

    pass

def cmphist(a, b):
    return cmp(a[0], b[0])
    
def _HistorySave(file):
    if (not init_history):
        return
    domimpl = xml.dom.getDOMImplementation()
    doc = domimpl.createDocument(None, "IPMIHistory", None)
    main = doc.documentElement
    i = 0
    for cmd in init_history:
        if (cmd != ""):
            helem = doc.createElement("hval")
            helem.setAttribute("idx", str(i))
            helem.setAttribute("val", cmd)
            main.appendChild(helem)
            i += 1
            pass
        pass
    try:
        info = os.stat(file)
        pass
    except:
        # File doesn't exist, create it.
        try:
            fd = os.open(file, os.O_WRONLY | os.O_CREAT,
                         stat.S_IRUSR | stat.S_IWUSR)
            os.close(fd)
            pass
        except:
            _oi_logging.error("Unable to create startup file " + file)
            return
        pass
    try:
        f = open(file, 'w')
        doc.writexml(f, indent='', addindent='\t', newl='\n')
    except:
        pass
    return

def _HistoryRestore(file):
    info = None
    try:
        info = os.stat(file)
    except:
        pass
    if (info):
        if ((info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)) != 0):
            sys.exit("The history file '" + file + "' is group or world"
                     + " accessible.  It contains passwords, and"
                     + " should be secure.  Not starting the GUI,"
                     + " please fix the problem first.")
            return
        pass
    try:
        doc = xml.dom.minidom.parse(file).documentElement
    except:
        return
    for c in doc.childNodes:
        if (c.nodeType == c.ELEMENT_NODE):
            try:
                idx = int(c.getAttribute("idx"))
                val = c.getAttribute("val")
                init_history.append( (idx, val) )
                pass
            except:
                pass
            pass
        pass
    init_history.sort(cmphist)
    return
