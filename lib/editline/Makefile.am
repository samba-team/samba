# $Id$

include $(top_srcdir)/Makefile.am.common

if do_roken_rename
ES = snprintf.c strdup.c strlcat.c
endif

AM_CPPFLAGS += $(ROKEN_RENAME)

man_MANS = editline.3

lib_LTLIBRARIES = libeditline.la
if el_compat
noinst_LTLIBRARIES = libel_compat.la
endif

noinst_PROGRAMS = testit

CHECK_LOCAL =

testit_LDADD = \
	libeditline.la \
	$(LIB_tgetent) \
	$(LIB_roken)

include_HEADERS = editline.h

libeditline_la_SOURCES = \
	edit_locl.h \
	complete.c \
	editline.c \
	sysunix.c \
	editline.h \
	roken_rename.h \
	unix.h \
	$(EXTRA_SOURCE)

EXTRA_SOURCE = $(ES) 

libel_compat_la_SOURCES = edit_compat.c edit_compat.h

EXTRA_DIST = $(man_MANS)

snprintf.c:
	$(LN_S) $(srcdir)/../roken/snprintf.c .
strdup.c:
	$(LN_S) $(srcdir)/../roken/strdup.c .
strlcat.c:
	$(LN_S) $(srcdir)/../roken/strlcat.c .
