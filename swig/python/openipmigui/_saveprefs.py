# _saveprefs.py
#
# Code to save/restore openipmi GUI preferences
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

import xml.dom
import xml.dom.minidom
import _oi_logging
import os
import stat
import sys

taghash = { }

class RestoreHandler:
    def __init__(self, tag):
        taghash[tag] = self
        return

    def restore(self, attrlist):
        return

    pass


def save(objlist, file):
    domimpl = xml.dom.getDOMImplementation()
    doc = domimpl.createDocument(None, "IPMIPrefs", None)
    main = doc.documentElement
    for obj in objlist:
        elem = doc.createElement(obj.getTag())
        obj.SaveInfo(doc, elem)
        main.appendChild(elem)
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
        pass
    except:
        _oi_logging.error("Unable to save startup file " + file)
        pass
    return

def restore(file):
    info = None
    try:
        info = os.stat(file)
    except:
        pass
    if (info):
        if ((info.st_mode & (stat.S_IRWXG | stat.S_IRWXO)) != 0):
            sys.exit("The file '" + file + "' is group or world"
                     + " accessible.  It contains passwords, and"
                     + " should be secure.  Not starting the GUI,"
                     + " please fix the problem first.")
            return
        pass
    try:
        doc = xml.dom.minidom.parse(file).documentElement
    except:
        pass
    else:
        for child in doc.childNodes:
            if (child.nodeType == child.ELEMENT_NODE):
                tag = child.nodeName
                if (tag in taghash):
                    taghash[tag].restore(child)
                    child = child.nextSibling
                    pass
                pass
            pass
        pass
    return
