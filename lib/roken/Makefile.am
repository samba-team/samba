# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libroken.a

libroken_a_SOURCES = \
	base64.c get_window_size.c getarg.c inaddr2str.o k_getpwnam.c	\
	k_getpwuid.c mini_inetd.c parse_time.c parse_units.c signal.c	\
	snprintf.c strcasecmp.c verify.c warnerr.c

libroken_a_LIBADD = @LIBOBJS@
