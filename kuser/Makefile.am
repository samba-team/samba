# $Id$

include $(top_srcdir)/cf/Makefile.am.common

INCLUDES += $(INCLUDE_krb4)

man_MANS = kinit.1 klist.1 kdestroy.1

bin_PROGRAMS = kinit kauth klist kdestroy

kinit_SOURCES = kinit.c kinit_options.c

kauth_SOURCES = kinit.c kauth_options.c

noinst_PROGRAMS = kfoo kverify

kauth_LDADD = \
	$(LIB_kafs) \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(LIB_krb4) \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/roken/libroken.la

kinit_LDADD = $(kauth_LDADD)

LDADD = \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/roken/libroken.la
