# $Id$

include $(top_srcdir)/Makefile.am.common

INCLUDES += $(INCLUDE_krb4)

bin_PROGRAMS = rsh

libexec_PROGRAMS = rshd

rsh_SOURCES  = rsh.c common.c rsh_locl.h

rshd_SOURCES = rshd.c common.c rsh_locl.h

LDADD = $(LIB_kafs) \
	$(LIB_krb5) \
	$(LIB_krb4) \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/roken/libroken.la
