# $Id$

include $(top_srcdir)/Makefile.am.common

INCLUDES += $(INCLUDE_readline)

sbin_PROGRAMS = kadmin

libexec_PROGRAMS = kadmind

kadmin_SOURCES = 						\
	ank.c cpw.c del.c dump.c ext.c get.c init.c kadmin.c	\
	load.c mod.c rename.c util.c kadmin_locl.h

kadmind_SOURCES = kadmind.c kadmin_locl.h

COMMON_LDADD = \
	$(top_builddir)/lib/hdb/libhdb.la \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/des/libdes.la \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(top_builddir)/lib/sl/libsl.a \
	$(LIB_readline) \
	$(top_builddir)/lib/roken/libroken.la \
	$(DBLIB)

kadmind_LDADD = $(top_builddir)/lib/kadm5/libkadm5srv.la $(COMMON_LDADD)
kadmin_LDADD = $(top_builddir)/lib/kadm5/libkadm5clnt.la $(COMMON_LDADD)
