# $Id$

AUTOMAKE_OPTIONS = no-dependencies

INCLUDES = -I$(top_builddir)/include -I$(srcdir)/.. -I$(srcdir)

lib_LIBRARIES = liberror.a

liberror_a_SOURCES = krb5_err.c asn1_err.c hdb_err.c error.c 

%.c: %.et
	$(SHELL) ./compile_et $<

krb5_err.o: asn1_err.c
