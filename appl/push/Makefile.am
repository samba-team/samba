# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4)

libexec_PROGRAMS	= push

push_SOURCES		= push.c

LDADD = -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes $(LIB_krb4) -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken
