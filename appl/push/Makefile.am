# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4) @HESIODINCLUDE@

bin_SCRIPTS		= pfrom

libexec_PROGRAMS	= push

push_SOURCES		= push.c

pfrom: pfrom.in
	sed -e "s!%bindir%!$(bindir)!" $(srcdir)/pfrom.in > $@
	chmod +x $@

LDADD = $(top_builddir)/lib/krb5/libkrb5.la \
	$(LIB_krb4) \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/roken/libroken.la
	@HESIODLIB@
