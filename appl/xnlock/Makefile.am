# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

XINCS = @X_CFLAGS@
XLIBS = @X_LIBS@ -lXt @X_PRE_LIBS@ -lX11 @X_EXTRA_LIBS@

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4) $(X_CFLAGS) -DBINDIR=\"$(bindir)\"

bin_PROGRAMS = xnlock
if KRB4
AFSLIB=$(top_builddir)/lib/kafs/libkafs.a $(LIB_krb4)
else
AFSLIB=
endif

LDADD = $(AFSLIB) $(top_builddir)/lib/krb5/libkrb5.a $(top_builddir)/lib/asn1/libasn1.a $(top_builddir)/lib/des/libdes.a $(top_builddir)/lib/roken/libroken.a $(XLIBS)
