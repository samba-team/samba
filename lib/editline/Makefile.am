# $Id$

include $(top_srcdir)/Makefile.am.common

if do_roken_rename
IS = -DROKEN_RENAME
ES = snprintf.c strdup.c
endif

INCLUDES += $(IS)

man_MANS = editline.3

lib_LIBRARIES = libeditline.a
if el_compat
noinst_LIBRARIES = libel_compat.a
else
noinst_LIBRARIES =
endif

noinst_PROGRAMS = testit

CHECK_LOCAL =

testit_LDADD = \
	libeditline.a \
	$(LIB_tgetent) \
	$(LIB_roken)

include_HEADERS = editline.h

libeditline_a_SOURCES = \
	complete.c \
	editline.c \
	sysunix.c \
	editline.h \
	roken_rename.h \
	unix.h \
	$(EXTRA_SOURCE)

EXTRA_SOURCE = $(ES) 

libel_compat_a_SOURCES = edit_compat.c

EXTRA_DIST = $(man_MANS)

snprintf.c:
	$(LN_S) $(srcdir)/../roken/snprintf.c .
strdup.c:
	$(LN_S) $(srcdir)/../roken/strdup.c .
