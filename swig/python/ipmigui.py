#!/usr/bin/env python

import pygtk
pygtk.require("2.0")
import gtk
import OpenIPMI


class IPMIGui:
    def delete_event(self, widget, event, data=None):
        gtk.main_quit()
        return gtk.FALSE


    def in_key_pass_group(self, event):
        if (event.state & gtk.gdk.CONTROL_MASK):
            return True
        return False


    def check_cmd_buffer_size(self):
        count = self.cmdbuffer.get_line_count()
        while (count > self.max_cmd_buffer_size):
            pos = self.cmdbuffer.get_start_iter()
            pos2 = self.cmdbuffer.get_start_iter()
            pos2.set_line(1)
            self.cmdbuffer.delete(pos, pos2)
            count = self.cmdbuffer.get_line_count()


    def check_log_buffer_size(self):
        count = self.logbuffer.get_line_count()
        while (count > self.max_log_buffer_size):
            pos = self.logbuffer.get_start_iter()
            pos2 = self.logbuffer.get_start_iter()
            pos2.set_line(1)
            self.logbuffer.delete(pos, pos2)
            count = self.logbuffer.get_line_count()


    def key_press_handler(self, widget, event, data=None):
        if (event.keyval == self.return_keyval):
            end = self.cmdbuffer.get_end_iter();
            start = self.cmdbuffer.get_end_iter();
            start.set_line_offset(2)
            text = self.cmdbuffer.get_text(start, end,
                                           include_hidden_chars=gtk.FALSE)
            print("Test: " + text)
            self.cmdbuffer.place_cursor(end)
            self.cmdbuffer.insert_at_cursor("\n> ")
            self.check_cmd_buffer_size()
            self.cmdvadjust.set_value(self.cmdvadjust.upper)
            return True
        elif (event.keyval == self.backspace_keyval):
            mark = self.cmdbuffer.get_insert();
            pos = self.cmdbuffer.get_iter_at_mark(mark);
            offset = pos.get_line_offset()
            if (offset <= 2):
                return
            curr = self.cmdbuffer.get_iter_at_mark(mark);
            pos.set_line_offset(offset-1)
            self.cmdbuffer.delete(pos, curr)
            self.cmdbuffer.place_cursor(pos)
            return True
        elif (event.keyval == self.delete_keyval):
            mark = self.cmdbuffer.get_insert();
            pos = self.cmdbuffer.get_iter_at_mark(mark);
            end = self.cmdbuffer.get_end_iter();
            if (pos.compare(end) >= 0):
                return
            next = self.cmdbuffer.get_iter_at_mark(mark);
            offset = next.get_line_offset()
            next.set_line_offset(offset+1)
            self.cmdbuffer.delete(pos, next)
            return True
        elif (event.keyval == self.left_keyval):
            mark = self.cmdbuffer.get_insert();
            pos = self.cmdbuffer.get_iter_at_mark(mark);
            offset = pos.get_line_offset()
            if (offset <= 2):
                # Don't let anything else handle this
                return True
        elif (event.keyval == self.right_keyval):
            pass # Send this on
        elif (event.keyval == self.up_keyval):
            return True
        elif (event.keyval == self.down_keyval):
            return True
        elif (event.keyval == self.home_keyval):
            mark = self.cmdbuffer.get_insert();
            pos = self.cmdbuffer.get_iter_at_mark(mark);
            pos.set_line_offset(3)
            self.cmdbuffer.place_cursor(pos);
            return True
        elif (event.keyval == self.end_keyval):
            self.cmdbuffer.place_cursor(self.cmdbuffer.get_end_iter());
            return True
        elif (len(event.string) == 0):
            pass
        elif (self.in_key_pass_group(event)):
            pass
        else:
            self.cmdbuffer.insert_at_cursor(event.string)
            return True

        # Pass everything else on
        return False


    def get_main_menu(self, window):
        self.accel_group = gtk.AccelGroup()
        self.item_factory = gtk.ItemFactory(gtk.MenuBar, "<main>",
                                            self.accel_group)
        self.item_factory.create_items(self.menu_items)
        window.add_accel_group(self.accel_group)
        return self.item_factory.get_widget("<main>")


    def get_tree(self, window):
        self.scrolledtree = gtk.ScrolledWindow()
        self.scrolledtree.set_policy(gtk.POLICY_AUTOMATIC,
                                     gtk.POLICY_AUTOMATIC)
        self.treestore = gtk.TreeStore(str)
        self.treeview = gtk.TreeView(self.treestore)
        self.treeview.set_enable_search(gtk.FALSE)
        self.tvcolumn = gtk.TreeViewColumn()
        # Set a dummy widget for the column header
        self.tvcolumn.set_widget(gtk.VBox())
        self.treeview.append_column(self.tvcolumn)
        self.cell = gtk.CellRendererText(editable=gtk.FALSE)
        self.tvcolumn.pack_start(self.cell, True)
        self.tvcolumn.add_attribute(self.cell, 'text', 0)

        self.scrolledtree.add(self.treeview)
        return self.scrolledtree


    def get_log(self, window):
        self.scrolledlog = gtk.ScrolledWindow()
        self.scrolledlog.set_policy(gtk.POLICY_AUTOMATIC,
                                     gtk.POLICY_AUTOMATIC)
        self.logview = gtk.TextView()
        self.logview.set_editable(gtk.FALSE)
        self.logbuffer = self.logview.get_buffer()
        self.logview.set_wrap_mode(gtk.WRAP_NONE)

        self.logbuffer.insert_at_cursor("OpenIPMI Logs...\n")
        self.scrolledlog.add(self.logview)
        self.logvadjust = self.scrolledlog.get_vadjustment()
        return self.scrolledlog

    
    def get_cmd(self, window):
        self.scrolledcmd = gtk.ScrolledWindow()
        self.scrolledcmd.set_policy(gtk.POLICY_AUTOMATIC,
                                     gtk.POLICY_AUTOMATIC)
        self.cmdview = gtk.TextView()
        self.cmdview.set_editable(gtk.FALSE)
        self.cmdbuffer = self.cmdview.get_buffer()
        self.cmdview.set_wrap_mode(gtk.WRAP_NONE)

        self.cmdbuffer.insert_at_cursor("> ")
        self.scrolledcmd.add(self.cmdview)
        self.cmdvadjust = self.scrolledcmd.get_vadjustment()
        return self.scrolledcmd

    
    def __init__(self):
        self.return_keyval = gtk.gdk.keyval_from_name("Return")
        self.left_keyval = gtk.gdk.keyval_from_name("Left")
        self.right_keyval = gtk.gdk.keyval_from_name("Right")
        self.up_keyval = gtk.gdk.keyval_from_name("Up")
        self.down_keyval = gtk.gdk.keyval_from_name("Down")
        self.backspace_keyval = gtk.gdk.keyval_from_name("BackSpace")
        self.delete_keyval = gtk.gdk.keyval_from_name("Delete")
        self.home_keyval = gtk.gdk.keyval_from_name("Home")
        self.end_keyval = gtk.gdk.keyval_from_name("End")

        self.max_cmd_buffer_size = 1000
        self.max_log_buffer_size = 1000

        self.window = gtk.Window(gtk.WINDOW_TOPLEVEL)
        self.window.set_size_request(200, 300)
        self.window.connect("key_press_event", self.key_press_handler)
        self.window.connect("delete_event", self.delete_event)
        vbox = gtk.VBox(gtk.FALSE, 1);
        self.menu_items = (
            ( "/_File",         None,           None, 0, "<Branch>" ),
            ( "/File/Quit",     "<control>Q",   gtk.main_quit, 0, None ),
            )
        self.window.set_title("IPMI GUI")
        self.window.add(vbox);

        menubar = self.get_main_menu(self.window);
        vbox.pack_start(menubar, gtk.FALSE, gtk.TRUE, 0)

        hbox = gtk.HBox(gtk.FALSE, 1)
        vbox.pack_start(hbox, gtk.TRUE, gtk.TRUE, 0)

        tree = self.get_tree(self.window)
        hbox.pack_start(tree, gtk.TRUE, gtk.TRUE, 0)

        log = self.get_log(self.window)
        hbox.pack_end(log, gtk.TRUE, gtk.TRUE, 0)

        cmd = self.get_cmd(self.window)
        vbox.pack_start(cmd, gtk.TRUE, gtk.TRUE, 0)

        self.window.show_all()
        self.cmdview.set_cursor_visible(gtk.TRUE)


    def new_log(self, log):
        self.logbuffer.insert_at_cursor(log)
        self.logbuffer.insert_at_cursor("\n")
        self.check_log_buffer_size()
        self.logvadjust.set_value(self.logvadjust.upper)


    def add_domain(self, name):
        store = self.treestore.append(None, [name])
        entities = self.treestore.append(store, ['Entities'])
        mcs = self.treestore.append(store, ['MCs'])
        return store, entities, mcs


    def remove_domain(self, store):
        self.treestore.remove(store);


    def add_entity(self, parent, name):
        return self.treestore.append(parent, name)

    
    def remove_entity(self, store):
        return self.treestore.remove(store)
    

class Entity:
    def __init__(self, domain, entity):
        self.domain = domain
        domain.entities[entity] = self
        self.store = 
        

class Domain:
    def entity_updated_cb(self, op, domain, entity):
        
        
    def __init__(self, main_handler, domain):
        self.main_handler = main_handler;
        self.domain = domain;
        self.name = domain.get_name();
        main_handler.domains[domain] = self
        self.entities = { };
        self.mcs = { };
        self.store, self.entities, self.mcs = main_handler.ui.add_domain(self.name);

    def remove(self):
        self.main_handler.ui.remove_domain(self.store);
        self.main_handler.domains.pop(self.domain);
        

class DomainHandler:
    def domain_change_cb(self, op, domain):
        if (op == "added"):
            Domain(self, domain)
        elif (op == "removed"):
            self.domains[domain].remove()

    def log(self, level, log):
        self.ui.new_log(level + ": " + log);

def main():
    gtk.main()
    return 0         

if __name__ =="__main__":
    main_handler = DomainHandler();
    main_handler.domains = { };
    OpenIPMI.init()
    OpenIPMI.add_domain_change_handler(main_handler);
    OpenIPMI.set_log_handler(main_handler);
    main_handler.ui = IPMIGui()
    OpenIPMI.open_domain2("d", ["lan", "-U", "minyard", "-P", "test",
                                "-p", "9000", "-H", "rmcpp_integ_sik",
                                "localhost"])
    main()
