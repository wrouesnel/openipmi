
AM_CFLAGS = -Wall -I$(top_srcdir)/include -DIPMI_CHECK_LOCKS

lib_LIBRARIES = libIPMIutils.a

libIPMIutils_a_SOURCES = md5.c md2.c ipmi_auth.c
libIPMIutils_a_LIBADD = 

noinst_PROGRAMS = test_md2 test_md5

test_md2_SOURCES = test_md2.c
test_md2_LDADD = 

test_md5_SOURCES = test_md5.c
test_md5_LDADD = 

TESTS = test_md2 test_md5
