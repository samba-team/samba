# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include 

bin_PROGRAMS = kpasswd

libexec_PROGRAMS = kpasswdd

kpasswdd_LDADD = -L$(top_builddir)/lib/hdb -lhdb $(LDADD)

LDADD = -L$(top_builddir)/lib/krb5  -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/roken -lroken
