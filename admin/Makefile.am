# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

CFLAGS = @CFLAGS@ $(WFLAGS)

INCLUDES = -I$(top_builddir)/include $(INCLUDE_readline)

man_MANS = ktutil.8

sbin_PROGRAMS = ktutil

ktutil_SOURCES = ktutil.c srvconvert.c

LDADD = \
	$(top_builddir)/lib/krb5/libkrb5.a \
	$(top_builddir)/lib/des/libdes.a \
	$(top_builddir)/lib/asn1/libasn1.a \
	$(top_builddir)/lib/sl/libsl.a \
	$(LIB_readline) \
	$(top_builddir)/lib/roken/libroken.a
