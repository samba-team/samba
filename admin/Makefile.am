# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include $(INCLUDE_readline)

man_MANS = ktutil.8

sbin_PROGRAMS = ktutil

ktutil_SOURCES = ktutil.c srvconvert.c

LDADD = -L$(top_builddir)/lib/krb5 -lkrb5 -L$(top_builddir)/lib/des -ldes -L$(top_builddir)/lib/asn1 -lasn1 -L$(top_builddir)/lib/sl -lsl $(LIB_readline) -L$(top_builddir)/lib/roken -lroken
