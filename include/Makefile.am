# $Id$

include $(top_srcdir)/Makefile.am.common

SUBDIRS = kadm5

noinst_PROGRAMS = bits

INCLUDES = -DHOST=\"$(CANONICAL_HOST)\"

include__DATA = krb5-types.h

krb5-types.h: bits
	./bits krb5-types.h
