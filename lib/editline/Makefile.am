# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libeditline.a
if el_compat
noinst_LIBRARIES = libel_compat.a
else
noinst_LIBRARIES =
endif

libeditline_a_SOURCES = complete.c editline.c sysunix.c
libel_compat_a_SOURCES = edit_compat.c
