# $Id$

AUTOMAKE_OPTIONS = no-dependencies

INCLUDES = -I$(top_builddir)/include -I$(srcdir)/.. -I$(srcdir)

lib_LIBRARIES = error

error_SOURCES = error.c krb5_err.c

%.c: %.et
	$(srcdir)/compile_et $<
