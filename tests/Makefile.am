# $Id$

include $(top_srcdir)/Makefile.am.common

SUBDIRS = db kdc gss

if ENABLE_SHARED
if HAVE_DLOPEN
SUBDIRS += plugin
endif
endif
