# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

if KRB4
AFSPROGS = afslog
else
AFSPROGS = 
endif
bin_PROGRAMS = $(AFSPROGS)

LDADD = $(top_builddir)/lib/kafs/libkafs.a $(LIB_krb4) $(top_builddir)/lib/krb5/libkrb5.a $(top_builddir)/lib/asn1/libasn1.a $(top_builddir)/lib/des/libdes.a $(top_builddir)/lib/roken/libroken.a
