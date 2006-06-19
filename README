
This is the OpenIPMI library, a library that makes simplifies building
complex IPMI management software.

What is IPMI?
=============

IPMI is a specification detailing how to detect and manage sensors in
a system.  It also specifies some chassis-level thing like power control,
reset, FRU (Field Replaceable Unit) information, and watchdogs.

However, IPMI has become much more than that.  Vendors have added
extensions to IPMI for doing many thing, including controlling LEDs,
relays, character displays, and managing hot-swapping components.  In
general, it has become the "standard" way to handle hardware
maintenance in a system.

IPMI specifies a set of interconnected intelligent Management
Controllers (MCs).  Each MC is a small CPU that manages a set of
sensors and/or output devices.  The "main" MC is called the Baseboard
Management Controller (BMC); it provides the external interfaces into
the system.

Each MC may have a set of Sensor Data Records (SDRs).  An SDR details
information about a sensor.  Some SDR records also have information
about entities, such as their name, the FRU information, and what
other entities they are contained in.

Entities are the physical objects in the system (boards, CPUs, fans,
power supplies, etc.)  A sensor is attached to the entity it monitors;
the SDR record tell what entity a sensor monitors.

IPMI specifies several external interfaces to the BMC.  One set is
local interfaces directly to a CPU, a local CPU connections is called
a system interface.  The other is external interfaces through a LAN,
serial port, or modem.  The external interfaces allow a system to be
managed even when it is turned off, since the BMC is always powered
when the system is plugged in.

IPMI has a strong bent toward complete "chassis" systems, basically a
box with one main board with CPUs; a BMC, and perhaps a few satellite
MCs in things like power supplies.  It is being rapidly adopted in
"shelf" systems, which has a set of slots where you can plug in
complete single-board computers.  In shelf systems, the BMC becomes a
central shelf manager that manages all the boards in the shelf.
Although IPMI was not designed for this, it does a pretty good job of
extending into this architecture.


What is OpenIPMI?
=================

Notice that in the description above, OpenIPMI was designed to aid
building "complex IPMI management software".  That's a carefully
chosen description.  

Most of the OpenIPMI library was designed for building complicated
systems that continuously monitor IPMI hardware.  It's not for little
things that simply want to get some information, do something, and
leave (unless that information is elaborate information).

OpenIPMI will connect with an IPMI controller, detect any management
controllers on the bus, get their SDRs, manage all the entities in the
system, manage the event log, and a host of other things.  As you
might imagine, that is a fairly lengthy process on a complex system.

OpenIPMI is also dynamic and event-driven.  It will come up and start
discovering things in the managed system.  As it discovers things, it
will report them to the software using it (assuming the software has
asked for this reporting).  This process of discovery is never done
from OpenIPMI's point of view; things can come and go in the system
and it will report these changes as it detects them.  This can be a
little confusing to people who want a static view of their system.
OpenIPMI has no static view (though it does have a current view).
When you make a connection, it will report when the connection is up;
but the system will be "empty".  You have to wait for OpenIPMI to
report the things it finds.

It is possible to use OpenIPMI's low-level connection code if you want
to do a direct connection to a BMC (through the LAN or system
interface).  You can see the code in sample/ipmicmd.c for an example
of how to do this.  Most of the other pieces of OpenIPMI are not
useful by themselves, though, because they are intrinsically tied
together.


Building and Configuring OpenIPMI
=================================

OpenIPMI is built with standard autoconf/automake.

You must configure OpenIPMI before you compile it.  To do this, change
to the main OpenIPMI directory and execute "./configure".  The
configure script will detect what is available in the system and
configure itself accordingly.

By default, the configure script will cause OpenIPMI to be installed
in the "/usr/local" prefix.  This means that the include files go into
/usr/local/include/OpenIPMI, the libraries go into /usr/local/lib, the
executables go into /usr/local/bin, etc. If you want to change the
prefix, use the "--prefix=<prefix>" option to configure.  For
instance, to install in /opt/OpenIPMI, you would do:
	  ./configure --prefix=/opt/OpenIPMI

Note that OpenIPMI will attempt to detect and use either the NET SNMP
or UCD SNMP libraries.  Note that if your NET SNMP or UCD SNMP library
is in a non-standard location, you will need to use the
'--with-ucdsnmp=<path>' option with configure to specify the actual
path to your library.  You also *must* have the development system for
your SNMP library installed.  If you don't have the development system
installed, just the runtime libraries, OpenIPMI will not detect or use
the SNMP libraries.  If you do not want to use the SNMP libraries even
if they are installed, you can specify '--with-ucdsnmp=no' as a
configure option.

After you have configured OpenIPMI, type "make" to build it.  To
install it in the prefix you defined, do "make install".

OpenIPMI requires the following packages:

  * popt
  * curses, ncurses or termcap

OpenIPMI can use, but does not require, the following packages:

  * netsnmp or ucdsnmp - netsnmp is the preferred SNMP package, but
    it will use either of these.  Without this, the sample programs
    will not be able to receive SNMP traps, but there is no functional
    change to the library.
  * openssl - This is required for IPMI 2.0 RMCP+ encryption and
    authentication support.  See FAQ item 2.22 for details.
  * glib (along with pkgconfig) - glib 2.0 is preferred, but glib 1.2
    will be used if 2.0 is not available.  This is simply an OS handler
    for glib and it not used for anything else in OpenIPMI itself, but
    is useful for users using glib.  Note that OpenIPMI will be able to
    use both glib 1.2 an glib 2.0 at the same time, but this is difficult
    and not recommended.
  * swig 1.3.21 or later - This is required for perl and python language
    support.  Without it, perl, python, and the GUI will not work.
  * perl - Support for writing scripts in the perl language that use
    the OpenIPMI library.
  * python - Support for writing scripts in the python language that use
    the OpenIPMI library.
  * Tcl/Tk - There is no Tcl language support (someone may contribute
    that, though).  However, A Tcl OS handler is provided so that
    Perl and Python may use the Tk widgets.  Without this, the GUI will
    not work.  Note that getting Tcl/Tk to work right can be difficult,
    see below for more details.
  * Tkinter/Tix - Python GUI libraries.  Required for the GUI to work.
  * gdbm - This is used on *nix for local SDR caching.  This is not
    required, but it *really* speeds up startup.

Note you need to install the development packages (generally ending in
-dev) of most of these for OpenIPMI to pick it up.  You can examine
the output of configure to make sure they are properly discovered.


Getting Tcl/Tk to work
======================

Tcl is installed in various places, and the configure script probably
won't find it.  If it doesn't, you must specify the install location
for Tcl by adding:
  --with-tclcflags=flags --with-tcllibs=lib
For instance, on my Debian Linux system, I have to specify:
  ./configure --with-tclcflags="-I /usr/include/tcl8.4" --with-tcllibs=-ltcl8.4
to make it work right.

If you don't get this right, you don't get a GUI!


Using ipmish
============

ipmish is a command interpreter that lets you execute IPMI operations,
get the results, etc.  It gives you the full power of OpenIPMI.  It
can easily be driven with a TCL script or the like.  See the man page
for more details.


The OpenIPMI GUI
================

The GUI is cleverly named openipmigui and provides a GUI interface to
most of OpenIPMI.  It also has the standard command language (like
ipmish) available in a window, so it has all the power of ipmish.

To use the GUI, you have to have the following optional packages:
  * swig 1.3.21 or later
  * python
  * Tcl/Tk
  * Tkinter/Tix

The GUI is documented in the openipmigui man page.


Using ipmi_ui
=============

ipmi_ui is a cheesy little tool that runs on top of the OpenIPMI
library.  It provides a command line and text-window based view into
an IPMI system.  A man page is included for it, if you want to know
more.

Note that ipmi_ui was written primarily for testing.  It does things
that users generally shouldn't do.  You can use it for examples, but
it touches things that are considered OpenIPMI internal, so be careful
what you use.  ipmish and the sample code is a much better example.


Perl/Python and OpenIPMI
========================

OpenIPMI has perl and python bindings using swig.  The public
interface of OpenIPMI is available, but the private interfaces are not
(and a few other things like SNMP trap support).  It is fully
function.

I was hoping that swig would generate documentation from the comments,
but it turns out that it does not do that.  You can look at
swig/OpenIPMI.i for the documentation on all the interfaces, and
swig/perl/sample and the gui in swig/python/openipmigui.py for a piece
of sample code that uses most of the interfaces.

The interface is object-oriented, so you have to know how to do OO
Perl or Pythong to use this.  It is like this because that is the most
natural way to use SWIG (and it makes more OO languages like python
easier).


OpenIPMI and SNMP
=================

The OpenIPMI ipmi_ui command has an optional trap handler.  It will
use incoming traps as an indication that something is waiting in the
SEL for it to fetch and immediately start a fetch.  You have to have
the UCD snmp library (or something compatible) installed for this to
work, and you have to start ipmi_ui with the '-snmp' option.  You must
do this as root, as the SNMP Trap port is 162.

You may ask why the trap is not directly used, why does it just
trigger an SEL fetch?  Well, that's because the IPMI trap does not
have enough information to determine the correct sensor (it's missing
the channel and LUN) and it does not have enough information to
correlate the SEL entries with the trap (It doesn't have the record ID
or necessarily the proper timestamp).

Also, OpenIPMI does not directly handle the traps.  Instead, it has an
interface to report a trap when it has been received.  OpenIPMI does
not want to assume the SNMP library being used; instead it lets the
user pick that library.  If you want an example of how to use the UCD
SNMP or NET SNMP libraries and hook them into OpenIPMI, the
ui/basic_ui.c file has an example of this.


What Else Comes with OpenIPMI?
==============================

It does include the utility "ipmicmd" which lets you do direct IPMI
commands to a connection.  ipmicmd can connect using the OpenIPMI
driver or via IPMI LAN.

OpenIPMI also includes a LAN to system interface converter, it can sit
on top of an OpenIPMI driver and supply a LAN connection to the BMC.
Note that to work the best, the LAN converter needs at least the v22
version of the OpenIPMI driver to support setting retries and timeouts
for messages.

Other sample code for using OpenIPMI is in the "samples" directory.


IPMI Documentation
==================

OpenIPMI includes a texinfo document in the "doc" directory.  It talks
a little about IPMI, must mostly about OpenIPMI.  It is required
reading for using OpenIPMI.  Read it carefully.

Unfortunately, the IPMI spec is also currently required reading for
using OpenIPMI.  Fortunately, you do not need to read the whole spec.
If you read the OpenIPMI document first, you can probably get by with
reading the following sections in the 1.5 spec:
 * 1.6 (overview)
 * 5.2 (for the error completion codes)
 * 33-36 (talking about sensors and entities)
 * 37.1 (talking about the main sensor SDR, mostly for learning about
   sensor capabilities).
OpenIPMI should hide the rest from you.

The OpenIPMI document is currently just an overview.  It should point
you in all the right directions, but it does not contain the actual
details of most OpenIPMI functions.  Those are currently documented in
the include files, so you will have to look through the include files
for how to use the functions.


OpenIPMI Source Structure
=========================

Note that parts of OpenIPMI could be used inside other systems.
However, the LGPL license may be a restriction.  If you are interested
in re-licensing parts of OpenIPMI, contact MontaVista software.

The source tree here consists of the following directories:

+---cmdlang - A command-line interpreter that gives access to the
|             OpenIPMI library.  Includes a user interface named
|             openipmish that demonstrates how to use it.
|  
+--- doc - The main documentation for OpenIPMI
|
+---glib - A glib OS handler.
|  
+---include
|   +---linux - linux-specific include files
|   \---OpenIPMI - User-visible include files for OpenIPMI
|       \---internal - Internal include files, only for plugins
|
+---lanserv - Code to provide a LAN interface to an IPMI device and
|             to provide an IPMI simulator
|  
+---lib - The man OpenIPMI code.  This is where all the logic for the
|         handling of IPMI messages is.
|  
+---libedit - A readline replacement that provides cmdlang/openipmish
|   |         with command line editing.
|   \---editline - Include files for libedit
|
+---man - The man pages for the 
|
+---sample - Sample code and utilities that use the OpenIPMI library.
|  
+---swig - The main interpreter interface.  swig is a program that
|   |      takes a general description of a C/C++ interface and
|   |      provides the equivalent interface in various interpreters.
|   +---perl - Perl-specific code for swig, including sample code and
|   |          tests.
|   \---python - Python-specific code for swig.
|       \---openipmigui - A GUI for OpenIPMI, written in Python.
|
+---tcl - A TCL OS handler
|
+---ui - A depracated UI for OpenIPMI.
|  
+---unix - A POSIX OS handler, one for threaded and one for
|          non-threaded applications/
|  
\---utils - General utility code used by both the OpenIPMI library
            and by the lanserv code.


