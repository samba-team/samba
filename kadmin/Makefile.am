# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_readline)

sbin_PROGRAMS = kadmin

kadmin_SOURCES = kadmin.c ank.c cpw.c del.c ext.c get.c

LDADD = $(top_builddir)/lib/kadm5/libkadm5srv.a $(top_builddir)/lib/hdb/libhdb.a $(top_builddir)/lib/krb5/libkrb5.a $(top_builddir)/lib/des/libdes.a $(top_builddir)/lib/asn1/libasn1.a $(top_builddir)/lib/sl/libsl.a $(LIB_readline) $(top_builddir)/lib/roken/libroken.a
