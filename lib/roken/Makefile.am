# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libroken.a

libroken_a_SOURCES = \
k_getpwuid.c k_getpwnam.c signal.c verify.c inaddr2str.o mini_inetd.c \
get_window_size.c warnerr.c snprintf.c

libroken_a_LIBADD = @LIBOBJS@
