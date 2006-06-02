# _domain.py
#
# openipmi GUI handling for domains
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

class PopupSelector:
    def __init__(self, handler, val, pd):
        self.handler = handler
        self.val = val;
        self.pd = pd
        return

    def handle(self):
        self.pd.done = True
        self.handler(self.val)
        return

    pass

class PopupDone:
    def __init__(self):
        self.done = False;
        pass

    def setdone(self, event):
        self.done = True
        return
    
    pass

def popup(ui, event, handlers, point=None):
    menu = Tix.Menu(ui, tearoff=0);
    pd = PopupDone()
    for h in handlers:
        if (len(h) >= 3):
            p = PopupSelector(h[1], h[2], pd)
            pass
        else:
            p = PopupSelector(h[1], None, pd)
            pass
        menu.add("command", command=p.handle, label=h[0])
        pass
    if (point == None):
        point = event
        pass
    menu.post(point.x_root, point.y_root)
    menu.grab_set_global()
    menu.bind("<FocusOut>", pd.setdone)
    menu.bind("<ButtonRelease-3>", pd.setdone)
    while (not pd.done):
        event.widget.tk.dooneevent()
        pass
    menu.grab_release()
    menu.destroy()
    return
