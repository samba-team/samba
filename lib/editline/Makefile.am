# $Id$

include $(top_srcdir)/cf/Makefile.am.common

man_MANS = editline.3

lib_LIBRARIES = libeditline.a
if el_compat
noinst_LIBRARIES = libel_compat.a
else
noinst_LIBRARIES =
endif

include_HEADERS = editline.h

libeditline_a_SOURCES = complete.c editline.c sysunix.c editline.h roken_rename.h unix.h
libel_compat_a_SOURCES = edit_compat.c

EXTRA_DIST = $(man_MANS) testit.c
