# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

YFLAGS = -d

INCLUDES = -I$(top_builddir)/include -I$(srcdir)

lib_LTLIBRARIES = libcom_err.la

bin_PROGRAMS = compile_et

compile_et_SOURCES = compile_et.c parse.y lex.l

libcom_err_la_SOURCES = error.c com_err.c

CLEANFILES = lex.c parse.c parse.h

$(compile_et_OBJECTS): parse.h

compile_et_LDADD = ../roken/libroken.la @LEXLIB@
