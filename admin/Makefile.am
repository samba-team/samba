# $Id$

include $(top_srcdir)/Makefile.am.common

INCLUDES += $(INCLUDE_readline)

man_MANS = ktutil.8

sbin_PROGRAMS = ktutil

ktutil_SOURCES = ktutil.c srvconvert.c

LDADD = \
	$(top_builddir)/lib/kadm5/libkadm5clnt.la \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/sl/libsl.a \
	$(LIB_readline) \
	$(top_builddir)/lib/roken/libroken.la
