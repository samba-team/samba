# $Id$

AUTOHEADER_FLAGS = no-dependencies foreign

#INCLUDES = -I$(top_builddir)/include -I/usr/athena/include
INCLUDES = -I$(top_builddir)/include -I$(top_builddir)/../k/include

bin_PROGRAMS = rsh

libexec_PROGRAMS = rshd

rsh_SOURCES  = rsh.c common.c

rshd_SOURCES = rshd.c common.c

#LDADD = -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L/usr/athena/lib -lkrb -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken
LDADD = -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/../k/lib/krb -lkrb -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken
