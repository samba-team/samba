# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

XINCS = @X_CFLAGS@
XLIBS = @X_LIBS@ -lXt @X_PRE_LIBS@ -lX11 @X_EXTRA_LIBS@

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4) $(X_CFLAGS) -DBINDIR=\"$(bindir)\"

bin_PROGRAMS = xnlock
if KRB4
AFSLIB=$(top_builddir)/lib/kafs/libkafs.a 
else
AFSLIB=
endif

LDADD = \
	$(top_builddir)/lib/kafs/libkafs.a \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(LIB_krb4) \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/roken/libroken.la \
	$(XLIBS)
