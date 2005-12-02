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
import logging

taghash = { }

class RestoreHandler:
    def __init__(self, tag):
        taghash[tag] = self

    def restore(self, attrlist):
        pass


def save(objlist, file):
    domimpl = xml.dom.getDOMImplementation()
    doc = domimpl.createDocument(None, None, None)
    main = doc.createElement("IPMIPrefs")
    doc.appendChild(main)
    for obj in objlist:
        elem = doc.createElement(obj.getTag())
        obj.SaveInfo(doc, elem)
        main.appendChild(elem)
    # FIXME - need try/except here
    f = open(file, 'w')
    doc.writexml(f, indent='', addindent='\t', newl='\n')

def restore(file):
    try:
        doc = xml.dom.minidom.parse(file).documentElement
    except:
        logging.error("Unable to parse startup file " + file)
    else:
        for child in doc.childNodes:
            if (child.nodeType == child.ELEMENT_NODE):
                tag = child.nodeName
                if (tag in taghash):
                    taghash[tag].restore(child)
                    child = child.nextSibling
