# $Id$

include $(top_srcdir)/Makefile.am.common

bin_PROGRAMS = bsearch

bsearch_SOURCES  = bsearch.c

man_MANS = bsearch.1

EXTRA_DIST = NTMakefile $(man_MANS)

LDADD = $(LIB_roken) $(LIB_vers) $(LIB_heimbase)
