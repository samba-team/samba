# $Id$

include $(top_srcdir)/Makefile.am.common

AM_CPPFLAGS += -I$(srcdir)/../mechglue \
	-I${srcdir}/../krb5 \
	-I${srcdir}/../asn1/include \
	$(INCLUDE_des) \
	$(INCLUDE_krb4)

gssdir = $(libdir)/gss

spnego_files =					\
	asn1_ContextFlags.x			\
	asn1_MechType.x				\
	asn1_MechTypeList.x			\
	asn1_NegotiationToken.x			\
	asn1_NegHints.x				\
	asn1_NegTokenInit.x			\
	asn1_NegTokenResp.x

BUILT_SOURCES = $(spnego_files:.x=.c)

gss_LTLIBRARIES = libmech_spnego.la
libmech_spnego_la_LDFLAGS = -version-info 1:0:0
libmech_spnego_la_LIBADD  = ../mechglue/libgssapi.la ../asn1/libasn1.la ../roken/libroken.la

include_HEADERS = gssapi_spnego.h

libmech_spnego_la_SOURCES =		\
	$(BUILT_SOURCES)	\
	accept_sec_context.c	\
	compat.c		\
	context_stubs.c		\
	cred_stubs.c		\
	external.c		\
	init_sec_context.c	

CLEANFILES = $(BUILT_SOURCES) $(spnego_files) spnego_asn1.h asn1_files

$(spnego_files) spnego_asn1.h: asn1_files

asn1_files: ../asn1/asn1_compile$(EXEEXT) $(srcdir)/spnego.asn1
	../asn1/asn1_compile$(EXEEXT) $(srcdir)/spnego.asn1 spnego_asn1

$(libmech_spnego_la_OBJECTS): spnego_asn1.h

