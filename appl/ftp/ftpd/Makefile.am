# $Id$

include $(top_srcdir)/cf/Makefile.am.common

INCLUDES += -I$(srcdir)/../common $(INCLUDE_krb4) -DFTP_SERVER

libexec_PROGRAMS = ftpd

if KRB4
krb4_sources = krb4.c kauth.c
endif
if KRB5
krb5_sources = gssapi.c gss_userok.c
endif

ftpd_SOURCES =		\
	extern.h	\
	ftpcmd.y	\
	ftpd.c		\
	ftpd_locl.h	\
	logwtmp.c	\
	pathnames.h	\
	popen.c		\
	security.c	\
	$(krb4_sources) \
	$(krb5_sources)

EXTRA_ftpd_SOURCES = krb4.c kauth.c gssapi.c gss_userok.c

$(ftpd_OBJECTS): security.h

security.c:
	@test -f security.c || $(LN_S) $(srcdir)/../ftp/security.c .
security.h:
	@test -f security.h || $(LN_S) $(srcdir)/../ftp/security.h .
krb4.c:
	@test -f krb4.c || $(LN_S) $(srcdir)/../ftp/krb4.c .
gssapi.c:
	@test -f gssapi.c || $(LN_S) $(srcdir)/../ftp/gssapi.c .

CLEANFILES = security.c security.h krb4.c gssapi.c ftpcmd.c

LDADD = ../common/libcommon.a \
	$(LIB_kafs) \
	$(LIB_gssapi) \
	$(LIB_krb5) \
	$(LIB_krb4) \
	$(top_builddir)/lib/otp/libotp.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la \
	@LIB_crypt@ $(DBLIB)
