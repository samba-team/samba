# $Id$

include $(top_srcdir)/Makefile.am.common

INCLUDES += -DROKEN_RENAME

YFLAGS = -d

include_HEADERS = sl.h

lib_LTLIBRARIES = libsl.la libss.la
libsl_la_LDFLAGS = -version-info 0:0:0
libss_la_LDFLAGS = -version-info 0:0:0

libsl_la_SOURCES = sl_locl.h sl.c roken_rename.h strtok_r.c snprintf.c
libss_la_SOURCES = $(libsl_la_SOURCES) ss.c ss.h

# install these?

noinst_PROGRAMS = mk_cmds

mk_cmds_SOURCES = make_cmds.c make_cmds.h parse.y lex.l snprintf.c

ssincludedir = $(includedir)/ss
ssinclude_HEADERS = ss.h

CLEANFILES = lex.c parse.c parse.h

$(mk_cmds_OBJECTS): parse.h

LDADD = ../roken/libroken.la $(LEXLIB)

strtok_r.c:
	$(LN_S) $(srcdir)/../roken/strtok_r.c .
snprintf.c:
	$(LN_S) $(srcdir)/../roken/snprintf.c .
