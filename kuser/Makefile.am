# $Id$

AUTOHEADER_FLAGS = no-dependencies

INCLUDES = -I$(top_builddir)/include 

bin_PROGRAMS = kinit klist kfoo

LDADD = -L$(top_builddir)/lib/krb5  -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken
