# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES	= libheimntlm.la

include_HEADERS = heimntlm.h heimntlm-protos.h

libheimntlm_la_SOURCES	= ntlm.c 

libheimntlm_la_LDFLAGS = -version-info 0:0:0

libheimntlm_la_LIBADD = \
	../krb5/libkrb5.la \
	$(LIBADD_roken)

$(srcdir)/heimntlm-protos.h:
	cd $(srcdir) && perl ../../cf/make-proto.pl -q -P comment -o heimntlm-protos.h $(libheimntlm_la_SOURCES) || rm -f heimntlm-protos.h

$(libheimntlm_la_OBJECTS): $(srcdir)/heimntlm-protos.h

TESTS = test_ntlm

check_PROGRAMS = test_ntlm

LDADD = libheimntlm.la $(LIB_roken)

