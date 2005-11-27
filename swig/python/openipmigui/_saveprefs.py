
import xml.dom;
import xml.dom.minidom;

taghash = { }

class RestoreHandler:
    def __init__(self, tag):
        taghash[tag] = self;

    def restore(self, mainhandler, attrlist):
        pass


def save(objlist, file):
    domimpl = xml.dom.getDOMImplementation();
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

def restore(file, mainhandler):
    doc = xml.dom.minidom.parse(file).documentElement
    for child in doc.childNodes:
        if (child.nodeType == child.ELEMENT_NODE):
            tag = child.nodeName
            if (tag in taghash):
                taghash[tag].restore(mainhandler, child)
        child = child.nextSibling
