# $Id$

AUTOMAKE_OPTIONS = foreign no-dependencies

CFLAGS = @CFLAGS@ $(WFLAGS)

INCLUDES = -I$(srcdir)/../common $(INCLUDE_readline) $(INCLUDE_krb4) $(INCLUDE_readline)

bin_PROGRAMS = ftp

if KRB4
krb4_sources = $(EXTRA_ftp_SOURCES)
else
krb4_sources = 
endif

ftp_SOURCES = \
	cmds.c \
	cmdtab.c \
	ftp.c \
	main.c \
	ruserpass.c \
	domacro.c \
	globals.c \
	security.c \
	$(krb4_sources) \
	gssapi.c

EXTRA_ftp_SOURCES = krb4.c kauth.c

LDADD = \
	../common/libcommon.a \
	$(top_builddir)/lib/gssapi/libgssapi.a \
	$(top_builddir)/lib/krb5/libkrb5.a \
	$(top_builddir)/lib/des/libdes.a \
	$(top_builddir)/lib/asn1/libasn1.a \
	$(LIB_krb4) \
	$(top_builddir)/lib/roken/libroken.a \
	$(LIB_readline)
