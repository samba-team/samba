# $Id$

include $(top_srcdir)/Makefile.am.common

INCLUDES += -I$(srcdir)/../common $(INCLUDE_readline) $(INCLUDE_krb4)

bin_PROGRAMS = ftp

if KRB4
krb4_sources = krb4.c kauth.c
endif
if KRB5
krb5_sources = gssapi.c
x = \
	$(top_builddir)/lib/gssapi/libgssapi.la \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/asn1/libasn1.la

endif

ftp_SOURCES = \
	cmds.c \
	cmdtab.c \
	extern.h \
	ftp.c \
	ftp_locl.h \
	ftp_var.h \
	main.c \
	pathnames.h \
	ruserpass.c \
	domacro.c \
	globals.c \
	security.c \
	security.h \
	$(krb4_sources) \
	$(krb5_sources)

EXTRA_ftp_SOURCES = krb4.c kauth.c gssapi.c

LIB_tgetent = @LIB_tgetent@

LDADD = \
	../common/libcommon.a \
	$(x) \
	$(LIB_krb4) \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la \
	$(LIB_readline)
