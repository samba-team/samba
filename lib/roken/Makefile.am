# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libroken.a

noinst_PROGRAMS = make-roken

libroken_a_SOURCES = \
	base64.c concat.c get_window_size.c getarg.c inaddr2str.o \
	k_getpwnam.c	\
	k_getpwuid.c mini_inetd.c parse_time.c parse_units.c signal.c	\
	snprintf.c strcasecmp.c verify.c warnerr.c

libroken_a_LIBADD = @LIBOBJS@

$(libroken_a_OBJECTS): roken.h

incdir = $(includedir)
inc_DATA = roken.h
idir = $(top_builddir)/include

all-local: $(inc_DATA)
	@for i in $(inc_DATA); do \
		if cmp -s  $$i $(idir)/$$i 2> /dev/null ; then :; else\
			echo " $(INSTALL_DATA) $$i $(idir)/$$i"; \
			$(INSTALL_DATA) $$i $(idir)/$$i; \
		fi ; \
	done

roken.h: make-roken
	@./make-roken > tmp.h ;\
	if [ -f roken.h ] && cmp -s tmp.h roken.h ; then rm -f tmp.h ; \
	else rm -f roken.h; mv tmp.h roken.h; fi

make-roken.c: roken.h.in roken.awk
	$(AWK) -f $(srcdir)/roken.awk $(srcdir)/roken.h.in > make-roken.c
