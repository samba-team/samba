# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

if KRB4
AFSPROGS = afslog
else
AFSPROGS = 
endif
bin_PROGRAMS = $(AFSPROGS)

LDADD = $(top_builddir)/lib/kafs/libkafs.a $(AIX_EXTRA_KAFS) \
	$(LIB_krb4) \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la
