# $Id$

include $(top_srcdir)/Makefile.am.common

INCLUDES += -DROKEN_RENAME

YFLAGS = -d

include_HEADERS = sl.h

lib_LTLIBRARIES = libsl.la

libsl_la_SOURCES = sl_locl.h sl.c ss.c ss.h roken_rename.h strtok_r.c snprintf.c

# install these?

noinst_PROGRAMS = mk_cmds

mk_cmds_SOURCES = make_cmds.c make_cmds.h parse.y lex.l snprintf.c

ssincludedir = $(includedir)/ss
#ssinclude_DATA = ss.h

$(mk_cmds_OBJECTS): parse.h

LDADD = ../roken/libroken.la $(LEXLIB)

strtok_r.c:
	$(LN_S) $(srcdir)/../roken/strtok_r.c .
snprintf.c:
	$(LN_S) $(srcdir)/../roken/snprintf.c .
