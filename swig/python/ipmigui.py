#!/usr/bin/env python

import pygtk
pygtk.require("2.0")
import gtk


class IPMIGui:
    def delete_event(self, widget, event, data=None):
        gtk.main_quit()
        return gtk.FALSE

    def get_main_menu(self, window):
        accel_group = gtk.AccelGroup()
        item_factory = gtk.ItemFactory(gtk.MenuBar, "<main>", accel_group)
        item_factory.create_items(self.menu_items)
        window.add_accel_group(accel_group)
        self.item_factory = item_factory
        return item_factory.get_widget("<main>")

    def get_tree(self, window):
        self.scrolledtree = gtk.ScrolledWindow(hadjustment=None, vadjustment=None)
        self.treestore = gtk.TreeStore(str)
        self.treeview = gtk.TreeView(self.treestore)
        self.tvcolumn = gtk.TreeViewColumn('Domains')
        self.treeview.append_column(self.tvcolumn)
        self.cell = gtk.CellRendererText()
        self.tvcolumn.pack_start(self.cell, True)
        self.tvcolumn.add_attribute(self.cell, 'text', 0)
        self.treeview.set_search_column(0)
        self.tvcolumn.set_sort_column_id(0)
        self.treeview.set_reorderable(True)
        return self.treeview;
        
    def __init__(self):
        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.connect("delete_event", self.delete_event)
        vbox = gtk.VBox(gtk.FALSE, 1);
        self.menu_items = (
            ( "/_File",         None,           None, 0, "<Branch>" ),
            ( "/File/Quit",     "<control>Q",   gtk.main_quit, 0, None ),
            )
        self.window.set_title("IPMI GUI")
        self.window.add(vbox);

        menubar = self.get_main_menu(self.window);
        vbox.pack_start(menubar, gtk.FALSE, gtk.TRUE, 0);

        hbox = gtk.HBox(gtk.FALSE, 1);
        vbox.pack_end(hbox, gtk.FALSE, gtk.TRUE, 0);

        tree = self.get_tree(self.window);
        hbox.pack_start(tree, gtk.FALSE, gtk.TRUE, 0);

        label = gtk.Label("Hello");
        hbox.pack_end(label, gtk.FALSE, gtk.TRUE, 0);
        self.window.show_all();


def main():
    gtk.main()
    return 0         


if __name__ =="__main__":
    IPMIGui()
    main()
