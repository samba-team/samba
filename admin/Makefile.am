# $Id$

AUTOHEADER_FLAGS = no-dependencies

INCLUDES = -I$(top_builddir)/include -I/usr/athena/include

bin_PROGRAMS = kdb_edit

kdb_edit_SOURCES = kdb_edit.c load.c ank.c dump.c init.c get.c delete.c

LDADD = -L$(top_builddir)/lib/hdb -lhdb -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L/usr/athena/lib -lsl -leditline -ledit -ltermcap

