# $Id$

include $(top_srcdir)/Makefile.am.common

SUBDIRS = kadm5

noinst_PROGRAMS = bits

INCLUDES = -DHOST=\"$(CANONICAL_HOST)\"

include_HEADERS = krb5-types.h

krb5-types.h: bits
	./bits krb5-types.h
