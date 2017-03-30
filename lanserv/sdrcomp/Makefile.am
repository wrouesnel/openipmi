
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

# Build host version of the program
sdrcomp_build_SOURCES = sdrcomp.c
BUILD_SDRCOMP_DEPS = $(top_srcdir)/lanserv/persist.c \
	$(top_srcdir)/utils/string.c
BUILD_SDRCOMP_SRCS = $(top_srcdir)/$(subdir)/sdrcomp.c
sdrcomp_build$(EXEEXT): $(BUILD_SDRCOMP_SRCS) $(BUILD_SDRCOMP_DEPS)
	$(BUILD_CC) -o $@ $(BUILD_SDRCOMP_SRCS) $(AM_CFLAGS) -lm
