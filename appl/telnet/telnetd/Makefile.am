# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I$(srcdir)/.. $(INCLUDE_krb4)

libexec_PROGRAMS = telnetd

telnetd_SOURCES  = telnetd.c state.c termstat.c slc.c sys_term.c \
		   utility.c global.c authenc.c

LDADD = -L../libtelnet -ltelnet -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes $(LIB_krb4) -L$(top_builddir)/lib/asn1 -lasn1 @LIB_tgetent@ -L$(top_builddir)/lib/roken -lroken
