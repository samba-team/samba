# $Id$

CFLAGS = @CFLAGS@ $(WFLAGS)

AUTOMAKE_OPTIONS = foreign no-dependencies

INCLUDES = -I$(srcdir)/../common $(INCLUDE_krb4) -DFTP_SERVER

libexec_PROGRAMS = ftpd

if KRB4
krb4_sources = $(EXTRA_ftpd_SOURCES)
else
krb4_sources = 
endif

ftpd_SOURCES =		\
	ftpd.c		\
	ftpcmd.y	\
	logwtmp.c	\
	popen.c		\
	security.c	\
	$(krb4_sources) \
	gssapi.c	\
	gss_userok.c

EXTRA_ftpd_SOURCES = krb4.c kauth.c

$(ftpd_OBJECTS): security.h

security.c:
	@test -f security.c || $(LN_S) $(srcdir)/../ftp/security.c .
security.h:
	@test -f security.h || $(LN_S) $(srcdir)/../ftp/security.h .
krb4.c:
	@test -f krb4.c || $(LN_S) $(srcdir)/../ftp/krb4.c .
gssapi.c:
	@test -f gssapi.c || $(LN_S) $(srcdir)/../ftp/gssapi.c .

CLEANFILES = security.c security.h krb4.c gssapi.c

if KRB4
afslib = $(top_builddir)/lib/kafs/libkafs.a
else
afslib =
endif

LDADD = ../common/libcommon.a \
	$(top_builddir)/lib/gssapi/libgssapi.a \
	$(afslib) \
	$(top_builddir)/lib/krb5/libkrb5.a \
	$(top_builddir)/lib/des/libdes.a \
	$(LIB_krb4) \
	$(top_builddir)/lib/asn1/libasn1.a \
	$(top_builddir)/lib/otp/libotp.a \
	$(top_builddir)/lib/roken/libroken.a @LIB_crypt@
