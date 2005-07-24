# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libhx509.la
libhx509_la_LDFLAGS = -version-info 1:0:0

BUILT_SOURCES = hx509_err.c hx509_err.h

libhx509_la_LIBADD = ../asn1/libasn1.la

libhx509_la_CPPFLAGS = -I$(srcdir)/ref $(INCLUDE_des)

libhx509_la_SOURCES = \
	cert.c \
	cms.c \
	crypto.c \
	file.c \
	hx509.h \
	hx509_err.c \
	hx509_err.h \
	keyset.c \
	ks_mem.c \
	ks_file.c \
	ks_null.c \
	ks_p12.c \
	lock.c \
	name.c \
	p11.c \
	print.c

$(libhx509_la_OBJECTS): $(srcdir)/hx509-protos.h $(srcdir)/hx509-private.h

$(srcdir)/hx509-protos.h:
	cd $(srcdir) && perl ../../cf/make-proto.pl -E HX509_LIB_FUNCTION -q -P comment -o hx509-protos.h $(libhx509_la_SOURCES) || rm -f hx509-protos.h

$(srcdir)/hx509-private.h:
	cd $(srcdir) && perl ../../cf/make-proto.pl -q -P comment -p hx509-private.h $(libhx509_la_SOURCES) || rm -f hx509-private.h

include_HEADERS = hx509.h hx509-protos.h hx509_err.h

noinst_PROGRAMS = hxtool

hxtool_SOURCES = hxtool.c

hxtool_CPPFLAGS = $(INCLUDE_des)
hxtool_LDADD = libhx509.la $(LIB_roken) ../sl/libsl.la $(LIB_des)
hxtool_LDFLAGS = -pthread

EXTRA_DIST = hx509_err.et

CLEANFILES = hx509_err.c hx509_err.h
