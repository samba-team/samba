# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_krb4)

bin_PROGRAMS = login
login_SOURCES = login.c read_string.c utmp_login.c utmpx_login.c tty.c stty_default.c

LDADD = $(top_builddir)/lib/krb5/libkrb5.la \
	$(LIB_krb4) \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/roken/libroken.la
