# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

SUFFIXES = .x .et .h

INCLUDES = $(WFLAGS) -I../asn1 -I$(srcdir)/../asn1

COMPILE_ET = ../com_err/compile_et

BUILT_SOURCES = asn1_Key.c asn1_Event.c asn1_HDBFlags.c asn1_hdb_entry.c \
	asn1_Salt.c hdb_err.c hdb_err.h

foo = asn1_Key.x asn1_Event.x asn1_HDBFlags.x asn1_hdb_entry.x asn1_Salt.x

CLEANFILES = $(BUILT_SOURCES) $(foo) hdb_asn1.h asn1_files

noinst_PROGRAMS = convert_db
LDADD = libhdb.la \
	../krb5/libkrb5.la \
	../asn1/libasn1.la \
	../des/libdes.la \
	../roken/libroken.la \
	$(DBLIB)

lib_LTLIBRARIES = libhdb.la

libhdb_la_SOURCES = hdb.c common.c db.c ndbm.c $(BUILT_SOURCES)

include_HEADERS = hdb.h
incdir = $(includedir)
inc_DATA = hdb_err.h hdb_asn1.h

libhdb_la_LIBADD = 

idir = $(top_builddir)/include

all-local: $(inc_DATA)
	@for i in $(inc_DATA); do \
		if cmp -s  $$i $(idir)/$$i 2> /dev/null ; then :; else\
			echo " $(INSTALL_DATA) $$i $(idir)/$$i"; \
			$(INSTALL_DATA) $$i $(idir)/$$i; \
		fi ; \
	done

$(foo) hdb_asn1.h: asn1_files

asn1_files: ../asn1/asn1_compile $(srcdir)/hdb.asn1
	../asn1/asn1_compile $(srcdir)/hdb.asn1 hdb_asn1

$(libhdb_la_OBJECTS): hdb_asn1.h hdb_err.h

.x.c:
	@cmp -s $< $@ 2> /dev/null || cp $< $@

.et.h:
	$(COMPILE_ET) $<

.et.c:
	$(COMPILE_ET) $<

hdb_err.h: hdb_err.et

hdb_err.c: hdb_err.et
