# $Id$

AUTOHEADER_FLAGS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

noinst_PROGRAMS = tcp_client tcp_server

tcp_client_SOURCES = tcp_client.c

tcp_server_SOURCES = tcp_server.c

LDADD = -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken
