# $Id$

include $(top_srcdir)/Makefile.am.common

INCLUDES += $(INCLUDE_krb4)

bin_PROGRAMS = login
login_SOURCES = login.c osfc2.c read_string.c utmp_login.c utmpx_login.c \
	tty.c stty_default.c login_locl.h


LDADD = $(top_builddir)/lib/krb5/libkrb5.la \
	$(LIB_krb4) \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_roken) \
	$(LIB_security)
