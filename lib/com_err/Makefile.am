# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

YFLAGS = -d

INCLUDES = -I$(top_builddir)/include -I$(srcdir)

lib_LIBRARIES = libcom_err.a

bin_PROGRAMS = compile_et

compile_et_SOURCES = compile_et.c parse.y lex.l

libcom_err_a_SOURCES = error.c com_err.c

$(compile_et_OBJECTS): parse.h

compile_et_LDADD = -L../roken -lroken
