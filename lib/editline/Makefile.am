# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libeditline.a

## hata

libeditline_a_SOURCES = foo.c

EXTRA_libeditline_a_SOURCES = \
complete.c edit_compat.c editline.c sysunix.c

libeditline_a_LIBADD = @editline_OBJS@
libeditline_a_DEPENDENCIES = $(libeditline_a_LIBADD)
