# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES	= libheimntlm.la

include_HEADERS = heimntlm.h heimntlm-protos.h

libheimntlm_la_SOURCES	= ntlm.c 

$(srcdir)/heimntlm-protos.h:
	cd $(srcdir) && perl ../../cf/make-proto.pl -q -P comment -o heimntlm-protos.h $(libheimntlm_la_SOURCES) || rm -f heimntlm-protos.h

$(libheimntlm_la_OBJECTS): $(srcdir)/heimntlm-protos.h
