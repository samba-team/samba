# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

SUFFIXES = .x

INCLUDES = -I../asn1 -I$(srcdir)/../asn1

BUILT_SOURCES = asn1_Key.c asn1_Event.c asn1_HDBFlags.c asn1_hdb_entry.c

foo = asn1_Key.x asn1_Event.x asn1_HDBFlags.x asn1_hdb_entry.x

CLEANFILES = $(BUILT_SOURCES) $(foo) hdb_asn1.h asn1_files


lib_LIBRARIES = libhdb.a

libhdb_a_SOURCES = hdb.c db.c ndbm.c $(BUILT_SOURCES)

$(foo) hdb_asn1.h: asn1_files

asn1_files: ../asn1/asn1_compile $(srcdir)/hdb.asn1
	../asn1/asn1_compile $(srcdir)/hdb.asn1 hdb_asn1

$(libhdb_a_OBJECTS): hdb_asn1.h
.x.c:
	@cmp -s $< $@ 2> /dev/null || cp $< $@
