# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = $(WFLAGS) -I$(top_builddir)/include 

man_MANS = kinit.1 klist.1 kdestroy.1

bin_PROGRAMS = kinit klist kdestroy

noinst_PROGRAMS = kfoo krenew kverify

LDADD = \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la
