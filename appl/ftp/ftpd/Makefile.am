# $Id$

CFLAGS = @CFLAGS@ $(WFLAGS)

AUTOMAKE_OPTIONS = foreign no-dependencies

INCLUDES = -I$(srcdir)/../common $(INCLUDE_krb4) -DFTP_SERVER

libexec_PROGRAMS = ftpd

ftpd_SOURCES =		\
	ftpd.c		\
	ftpcmd.y	\
	logwtmp.c	\
	popen.c		\
	security.c	\
	krb4.c		\
	kauth.c		\
	gssapi.c

$(ftpd_SOURCES): security.h

security.c:
	$(LN_S) $(srcdir)/../ftp/security.c .
security.h:
	$(LN_S) $(srcdir)/../ftp/security.h .
krb4.c:
	$(LN_S) $(srcdir)/../ftp/krb4.c .
gssapi.c:
	$(LN_S) $(srcdir)/../ftp/gssapi.c .

CLEANFILES = security.c security.h krb4.c gssapi.c

LDADD = ../common/libcommon.a \
	$(top_builddir)/lib/gssapi/libgssapi.a \
	$(top_builddir)/lib/kafs/libkafs.a \
	$(top_builddir)/lib/krb5/libkrb5.a \
	$(top_builddir)/lib/des/libdes.a \
	$(LIB_krb4) \
	$(top_builddir)/lib/asn1/libasn1.a \
	$(top_builddir)/lib/otp/libotp.a \
	$(top_builddir)/lib/roken/libroken.a
