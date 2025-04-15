man7_MANS		= quic.man
EXTRA_DIST		= $(man7_MANS)

lib_LTLIBRARIES		= libquic.la
libquic_la_SOURCES	= client.c handshake.c server.c
libquic_la_CPPFLAGS	= -I$(top_builddir)/libquic/
libquic_la_CFLAGS	= -Werror -Wall $(LIBGNUTLS_CFLAGS)
libquic_la_LIBADD	= $(LIBGNUTLS_LIBS)
libquic_la_LDFLAGS	= -version-info 1:0:0

libcnetinetdir		= $(includedir)/netinet
libcnetinet_HEADERS	= netinet/quic.h

if !BUILTIN_MODULES
libquic_la_CPPFLAGS	+= -I$(top_builddir)/modules/include/uapi/

libclinuxdir		= $(includedir)/linux
libclinux_HEADERS	= $(top_builddir)/modules/include/uapi/linux/quic.h
endif

pkgconfigdir		= $(libdir)/pkgconfig
pkgconfig_DATA		= libquic.pc

MAINTAINERCLEANFILES	= Makefile.in
