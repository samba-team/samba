# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

noinst_PROGRAMS = tcp_client tcp_server gssapi_server gssapi_client \
	uu_server uu_client

tcp_client_SOURCES = tcp_client.c common.c

tcp_server_SOURCES = tcp_server.c common.c

gssapi_server_SOURCES = gssapi_server.c gss_common.c common.c

gssapi_client_SOURCES = gssapi_client.c gss_common.c common.c

uu_server_SOURCES = uu_server.c common.c

uu_client_SOURCES = uu_client.c common.c

gssapi_server_LDADD = $(top_builddir)/lib/gssapi/libgssapi.a $(LDADD)

gssapi_client_LDADD = $(top_builddir)/lib/gssapi/libgssapi.a $(LDADD)

LDADD = $(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/roken/libroken.la
