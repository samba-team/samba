# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

YFLAGS = -d

INCLUDES = -I$(top_builddir)/include

lib_LIBRARIES = libsl.a

libsl_a_SOURCES = sl.c ss.c

# install these?
noinst_PROGRAMS = mk_cmds
#incdir = $(includedir)/ss
#inc_DATA = ss.h

mk_cmds_SOURCES = make_cmds.c parse.y lex.l

$(mk_cmds_OBJECTS): parse.h

LDADD = ../roken/libroken.a @LEXLIB@
