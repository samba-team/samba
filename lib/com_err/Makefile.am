# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include -I$(srcdir)

lib_LIBRARIES = liberror.a libcom_err.a

SUFFIXES = .et .h

incdir = $(includedir)
inc_DATA = asn1_err.h krb5_err.h heim_err.h
idir = $(top_builddir)/include

CLEANFILES = asn1_err.c asn1_err.h krb5_err.c krb5_err.h heim_err.c heim_err.h

liberror_a_SOURCES = krb5_err.c asn1_err.c error.c heim_err.c

libcom_err_a_SOURCES = error.c comerr.c

all-local: $(inc_DATA)
	@for i in $(inc_DATA); do \
		if cmp -s  $$i $(idir)/$$i 2> /dev/null ; then :; else\
			echo " $(INSTALL_DATA) $$i $(idir)/$$i"; \
			$(INSTALL_DATA) $$i $(idir)/$$i; \
		fi ; \
	done
.et.c:
	$(SHELL) ./compile_et $<

.et.h:
	$(SHELL) ./compile_et $<

krb5_err.o: asn1_err.c
