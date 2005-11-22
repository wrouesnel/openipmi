#!/usr/bin/env python

import pygtk
pygtk.require("2.0")
import gtk
import OpenIPMI


class IPMIGui:
    def delete_event(self, widget, event, data=None):
        gtk.main_quit()
        return False


    def open_domain(self, w, data):
        print("open")

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
                                           include_hidden_chars=False)
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
        self.treeview.set_enable_search(False)
        self.tvcolumn = gtk.TreeViewColumn()
        # Set a dummy widget for the column header
        self.tvcolumn.set_widget(gtk.VBox())
        self.treeview.append_column(self.tvcolumn)
        self.cell = gtk.CellRendererText()
        self.tvcolumn.pack_start(self.cell, True)
        self.tvcolumn.add_attribute(self.cell, 'text', 0)

        self.scrolledtree.add(self.treeview)
        return self.scrolledtree


    def get_log(self, window):
        self.scrolledlog = gtk.ScrolledWindow()
        self.scrolledlog.set_policy(gtk.POLICY_AUTOMATIC,
                                     gtk.POLICY_AUTOMATIC)
        self.logview = gtk.TextView()
        self.logview.set_editable(False)
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
        self.cmdview.set_editable(False)
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
        self.window.set_size_request(500, 300)
        self.window.connect("key_press_event", self.key_press_handler)
        self.window.connect("delete_event", self.delete_event)
        vbox = gtk.VBox(False, 1);
        self.menu_items = (
            ( "/_File",         None,           None, 0, "<Branch>" ),
            ( "/File/Quit",     "<control>Q",   gtk.main_quit, 0, None ),
            ( "/File/Open Domain","<control>O", self.open_domain, 0, None ),
            )
        self.window.set_title("IPMI GUI")
        self.window.add(vbox);

        menubar = self.get_main_menu(self.window);
        vbox.pack_start(menubar, False, True, 0)

        hbox = gtk.HPaned()
        vbox.pack_start(hbox, True, True, 0)

        tree = self.get_tree(self.window)
        hbox.add1(tree)

        log = self.get_log(self.window)
        hbox.add2(log)
        hbox.set_position(200)

        cmd = self.get_cmd(self.window)
        vbox.pack_start(cmd, True, True, 0)

        self.window.show_all()
        self.cmdview.set_cursor_visible(True)


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
    

    def add_mc(self, parent, name):
        return self.treestore.append(parent, name)

    
    def remove_mc(self, store):
        return self.treestore.remove(store)
    

class Entity:
    def __init__(self, domain, entity):
        self.domain = domain
        self.entity = entity
        domain.entities[entity] = self
        self.ui = domain.ui;
        self.store = self.ui.add_entity(domain.entity_store, [entity.get_name()])

    def remove(self):
        self.ui.remove_entity(self.store)
        self.domain.entities.pop(self.entity)


class MC:
    def __init__(self, domain, mc):
        self.domain = domain
        self.mc = mc
        domain.mcs[mc] = self
        self.ui = domain.ui;
        self.store = self.ui.add_mc(domain.mc_store, [mc.get_name()])

    def remove(self):
        self.ui.remove_mc(self.store)
        self.domain.mcs.pop(self.mc)


class Domain:
    def entity_update_cb(self, op, domain, entity):
        if (op == "added"):
            Entity(self, entity)
        elif (op == "removed"):
            self.entities[entity].remove()
        
    def mc_update_cb(self, op, domain, mc):
        if (op == "added"):
            MC(self, mc)
        elif (op == "removed"):
            self.entities[mc].remove()
        
    def __init__(self, main_handler, domain):
        self.main_handler = main_handler;
        self.domain = domain;
        self.name = domain.get_name();
        self.ui = main_handler.ui
        domain.add_entity_update_handler(self)
        domain.add_mc_update_handler(self)
        main_handler.domains[domain] = self
        self.entities = { }
        self.mcs = { }
        self.store, self.entity_store, self.mc_store = self.ui.add_domain(self.name);

    def remove(self):
        self.ui.remove_domain(self.store);
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
                                "-p", "9000", "localhost"])
    main()
