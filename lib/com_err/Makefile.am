# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I$(srcdir)

lib_LIBRARIES = liberror.a

SUFFIXES = .et

CLEANFILES = asn1_err.c asn1_err.h hdb_err.c hdb_err.h \
	krb5_err.c krb5_err.h heim_err.c heim_err.h

liberror_a_SOURCES = krb5_err.c asn1_err.c hdb_err.c error.c heim_err.c

.et.c:
	$(SHELL) ./compile_et $<

krb5_err.o: asn1_err.c
