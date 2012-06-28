#!/usr/bin/python

# sample2
#
# A sample file that does a "get device id" every 5 seconds
#
# Author: MontaVista Software, Inc.
#         Corey Minyard <minyard@mvista.com>
#         source@mvista.com
#
# Copyright 2011 MontaVista Software Inc.
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

import time
import sys
import OpenIPMI

class Handlers:
    def __init__(self, name):
        self.name = name
        self.mc = None
        return

    def log(self, level, log):
	print level + ": " + log
        return

    def conn_change_cb(self, domain, err, conn_num, port_num, still_connected):
        print "Conn up"
        return

    def domain_close_done_cb(self):
	self.name = "done"
        return

    def domain_iter_mc_cb(self, domain, mc):
        print "MC: " + mc.get_name()
        if mc.get_name() == "test(0.20)":
            # This is the one we want
            self.mc = mc.get_id();
        return

    def domain_up_cb(self, domain):
	domain.iterate_mcs(self)
        return

    def mc_cmd_cb(self, mc, netfn, cmd, response):
        print "got response: " + str(response)
        return

    def mc_cb(self, mc):
        mc.send_command(0, 6, 1, [], self)
        return

    def quit(self):
        del self.mc
        OpenIPMI.set_log_handler(DummyLogHandler())
        OpenIPMI.shutdown_everything()
        print "done"
        sys.exit(0)
        return

class DummyLogHandler:
    def __init__(self):
        pass

    def log(self, level, log):
        sys.stderr.write(level + ": " + log + "\n")


OpenIPMI.enable_debug_malloc()
OpenIPMI.init_posix()

main_handler = Handlers("hello")

OpenIPMI.set_log_handler(main_handler)

a = OpenIPMI.open_domain2("test", ["-noall",] + sys.argv[1:],
                          main_handler, main_handler)
if not a:
    print "open failed"
    sys.exit(1)
    pass
del a

nexttime = time.time()
num_poll = 1
while main_handler.name != "done" and num_poll <= 2:
    OpenIPMI.wait_io(1000)
    now = time.time()
    if main_handler.mc and now >= nexttime:
        nexttime += 5
	num_poll += 1
        if num_poll < 2:
	    main_handler.mc.to_mc(main_handler)
    pass

main_handler.quit()
