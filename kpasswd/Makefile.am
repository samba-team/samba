# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include 

man_MANS = kpasswd.1 kpasswdd.8

bin_PROGRAMS = kpasswd

libexec_PROGRAMS = kpasswdd

kpasswdd_LDADD = \
	$(top_builddir)/lib/kadm5/libkadm5srv.a \
	$(top_builddir)/lib/hdb/libhdb.a \
	$(LDADD) \
	$(DBLIB)

LDADD = $(top_builddir)/lib/krb5/libkrb5.a \
	$(top_builddir)/lib/des/libdes.a \
	$(top_builddir)/lib/asn1/libasn1.a \
	$(top_builddir)/lib/roken/libroken.a
