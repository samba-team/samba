# $Id$

AUTOHEADER_FLAGS = no-dependencies

INCLUDES = -I$(top_builddir)/include 

bin_PROGRAMS = load dump ank extkeytab

LDADD = -L$(top_builddir)/lib/hdb -lhdb -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/asn1 -lasn1

