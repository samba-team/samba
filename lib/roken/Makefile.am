# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

INCLUDES = -I$(top_builddir)/include

CLEANFILES = roken.h make-roken.c print_version.h

lib_LTLIBRARIES = libroken.la

noinst_PROGRAMS = make-roken make-print-version

make_print_version_LDADD = $(LIB_krb4)

libroken_la_SOURCES =		\
	base64.c		\
	concat.c		\
	emalloc.c		\
	erealloc.c		\
	estrdup.c		\
	get_window_size.c	\
	getarg.c		\
	inaddr2str.c		\
	issuid.c		\
	k_getpwnam.c		\
	k_getpwuid.c		\
	mini_inetd.c		\
	net_read.c		\
	net_write.c		\
	parse_time.c		\
	parse_units.c		\
	print_version.c		\
	resolve.c		\
	roken_gethostby.c	\
	signal.c		\
	snprintf.c		\
	strcat_truncate.c	\
	strcpy_truncate.c	\
	verify.c		\
	warnerr.c

libroken_la_LIBADD = @LTLIBOBJS@

$(LTLIBOBJS) $(libroken_la_OBJECTS): roken.h

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

print_version.lo: print_version.h

print_version.h: make-print-version
	./make-print-version print_version.h
