
AM_CFLAGS = -Wall -Wsign-compare -I$(top_srcdir)/include \
	-I$(top_srcdir)/lanserv -I$(top_srcdir)/utils

AM_CPPFLAGS = -DSTATEDIR='"$(localstatedir)"'

bin_PROGRAMS = sdrcomp
noinst_PROGRAMS = sdrcomp_build

# sdrcomp.c #includes persist.c and string.c
sdrcomp_DEPENDENCIES = $(top_srcdir)/lanserv/persist.c \
	$(top_srcdir)/utils/string.c
sdrcomp_SOURCES = sdrcomp.c
sdrcomp_LDFLAGS = -lm

sdrcomp_build_DEPENDENCIES = $(top_srcdir)/lanserv/persist.c \
	$(top_srcdir)/utils/string.c
sdrcomp_build_SOURCES = sdrcomp.c
sdrcomp_build_LDFLAGS = -lm
sdrcomp_build_CC = $(BUILD_CC)

# Host version of the program
BUILD_SDRCOMP_SRCS = $(top_srcdir)/$(subdir)/sdrcomp.c \
		$(top_srcdir)/utils/string.c
sdrcomp.build: $(BUILD_SDRCOMP_SRCS) $(top_srcdir)/lanserv/persist.c
	$(BUILD_CC) -o $@ $(BUILD_SDRCOMP_SRCS) $(AM_CFLAGS) -lm
