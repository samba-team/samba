# $Id$

AUTOHEADER_FLAGS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I$(srcdir)/..

libexec_PROGRAMS = telnetd

telnetd_SOURCES  = telnetd.c state.c termstat.c slc.c sys_term.c \
		   utility.c global.c authenc.c

LDADD = -L../libtelnet -ltelnet -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/asn1 -lasn1 @LIB_tgetent@ -L$(top_builddir)/lib/roken -lroken
