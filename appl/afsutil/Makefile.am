# $Id$

include $(top_srcdir)/Makefile.am.common

if KRB4
AFSPROGS = afslog
endif
bin_PROGRAMS = $(AFSPROGS)

EXTRA_bin_PROGRAMS = afslog

LDADD = $(LIB_kafs) \
	$(LIB_krb4) \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la
