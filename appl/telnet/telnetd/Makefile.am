# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I$(srcdir)/.. $(INCLUDE_krb4)

libexec_PROGRAMS = telnetd

telnetd_SOURCES  = telnetd.c state.c termstat.c slc.c sys_term.c \
		   utility.c global.c authenc.c

LDADD = \
	../libtelnet/libtelnet.a \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/des/libdes.la \
	$(LIB_krb4) \
	$(top_builddir)/lib/asn1/libasn1.la \
	@LIB_tgetent@ \
	@LIB_logwtmp@ \
	$(top_builddir)/lib/roken/libroken.la
