# $Id$

AUTOHEADER_FLAGS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I/usr/athena/include

bin_PROGRAMS = rsh

rsh_SOURCES  = rsh.c

LDADD = -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L/usr/athena/lib -lkrb -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken
