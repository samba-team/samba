# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_readline)

man_MANS = kdb_edit.8 ktutil.8

sbin_PROGRAMS = kdb_edit ktutil

kdb_edit_SOURCES =				\
		ank.c				\
		delete.c			\
		dump.c				\
		extkeytab.c			\
		get.c				\
		life.c				\
		init.c				\
		kdb_edit.c			\
		load.c				\
		mod.c				\
		util.c

ktutil_SOURCES = ktutil.c srvconvert.c

LDADD = -L$(top_builddir)/lib/hdb -lhdb -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/sl -lsl $(LIB_readline) -L$(top_builddir)/lib/roken -lroken
