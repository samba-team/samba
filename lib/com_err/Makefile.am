# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I$(srcdir)

lib_LIBRARIES = libcom_err.a

bin_PROGRAMS = compile_et

libcom_err_a_SOURCES = error.c comerr.c

compile_et: $(srcdir)/compile_et.in
	sed -e 's/@awk@/$(AWK)/' -e "/#awksrc/r $(srcdir)/compile_et.awk" $(srcdir)/compile_et.in > compile_et
	chmod +x compile_et
