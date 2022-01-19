# $Id$

include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS +=			    \
    -I$(srcdir)/../krb5		    \
    -I$(srcdir)/../gssapi	    \
    -I$(srcdir)/../gssapi/mech	    \
    -I$(top_srcdir)/include/gssapi  \
    -I$(top_builddir)/include/gssapi

noinst_LTLIBRARIES = libgss_preauth.la
include_HEADERS = $(srcdir)/gss-preauth-protos.h $(srcdir)/gss-preauth-private.h

libgss_preauth_la_SOURCES = pa_client.c pa_common.c

ALL_OBJECTS = $(include_HEADERS) $(libgss_preauth_la_OBJECTS)

$(libgss_preauth_la_OBJECTS): $(include_HEADERS)

$(srcdir)/gss-preauth-protos.h: $(libgss_preauth_la_SOURCES)
	cd $(srcdir); perl ../../cf/make-proto.pl -q -P comment -o gss-preauth-protos.h $(libgss_preauth_la_SOURCES) || rm -f gss-preauth-protos.h

$(srcdir)/gss-preauth-private.h: $(libgss_preauth_la_SOURCES)
	cd $(srcdir); perl ../../cf/make-proto.pl -q -P comment -p gss-preauth-private.h $(libgss_preauth_la_SOURCES) || rm -f gss-preauth-private.h
