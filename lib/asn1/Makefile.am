# $Id$

AUTOMAKE_OPTIONS = no-dependencies foreign

WFLAGS=@WFLAGS@
CFLAGS=$(WFLAGS) @CFLAGS@

YFLAGS = -d
#YACCFLAGS = $(YFLAGS)

#lib_LIBRARIES = libasn1.a
lib_LTLIBRARIES = libasn1.la

COMPILE_ET = ../com_err/compile_et

SUFFIXES = .et .x .h

BUILT_SOURCES =					\
	asn1_APOptions.c			\
	asn1_AP_REP.c				\
	asn1_AP_REQ.c				\
	asn1_AS_REP.c				\
	asn1_AS_REQ.c				\
	asn1_Authenticator.c			\
	asn1_AuthorizationData.c		\
	asn1_Checksum.c				\
	asn1_EncAPRepPart.c			\
	asn1_EncASRepPart.c			\
	asn1_EncKDCRepPart.c			\
	asn1_EncKrbCredPart.c			\
	asn1_EncKrbPrivPart.c			\
	asn1_EncTGSRepPart.c			\
	asn1_EncTicketPart.c			\
	asn1_EncryptedData.c			\
	asn1_EncryptionKey.c			\
	asn1_ETYPE_INFO.c			\
	asn1_ETYPE_INFO_ENTRY.c			\
	asn1_HostAddress.c			\
	asn1_HostAddresses.c			\
	asn1_KDCOptions.c			\
	asn1_KDC_REP.c				\
	asn1_KDC_REQ.c				\
	asn1_KDC_REQ_BODY.c			\
	asn1_KRB_CRED.c				\
	asn1_KRB_ERROR.c			\
	asn1_KRB_PRIV.c				\
	asn1_KRB_SAFE.c				\
	asn1_KRB_SAFE_BODY.c			\
	asn1_KerberosTime.c			\
	asn1_KrbCredInfo.c			\
	asn1_LastReq.c				\
	asn1_METHOD_DATA.c			\
	asn1_PA_DATA.c				\
	asn1_PA_ENC_TS_ENC.c			\
	asn1_Principal.c			\
	asn1_PrincipalName.c			\
	asn1_Realm.c				\
	asn1_TGS_REP.c				\
	asn1_TGS_REQ.c				\
	asn1_Ticket.c				\
	asn1_TicketFlags.c			\
	asn1_TransitedEncoding.c		\
	asn1_err.h				\
	asn1_err.c

foo =						\
	asn1_APOptions.x			\
	asn1_AP_REP.x				\
	asn1_AP_REQ.x				\
	asn1_AS_REP.x				\
	asn1_AS_REQ.x				\
	asn1_Authenticator.x			\
	asn1_AuthorizationData.x		\
	asn1_Checksum.x				\
	asn1_EncAPRepPart.x			\
	asn1_EncASRepPart.x			\
	asn1_EncKDCRepPart.x			\
	asn1_EncKrbCredPart.x			\
	asn1_EncKrbPrivPart.x			\
	asn1_EncTGSRepPart.x			\
	asn1_EncTicketPart.x			\
	asn1_EncryptedData.x			\
	asn1_EncryptionKey.x			\
	asn1_ETYPE_INFO.x			\
	asn1_ETYPE_INFO_ENTRY.x			\
	asn1_HostAddress.x			\
	asn1_HostAddresses.x			\
	asn1_KDCOptions.x			\
	asn1_KDC_REP.x				\
	asn1_KDC_REQ.x				\
	asn1_KDC_REQ_BODY.x			\
	asn1_KRB_CRED.x				\
	asn1_KRB_ERROR.x			\
	asn1_KRB_PRIV.x				\
	asn1_KRB_SAFE.x				\
	asn1_KRB_SAFE_BODY.x			\
	asn1_KerberosTime.x			\
	asn1_KrbCredInfo.x			\
	asn1_LastReq.x				\
	asn1_METHOD_DATA.x			\
	asn1_PA_DATA.x				\
	asn1_PA_ENC_TS_ENC.x			\
	asn1_Principal.x			\
	asn1_PrincipalName.x			\
	asn1_Realm.x				\
	asn1_TGS_REP.x				\
	asn1_TGS_REQ.x				\
	asn1_Ticket.x				\
	asn1_TicketFlags.x			\
	asn1_TransitedEncoding.x


noinst_PROGRAMS = asn1_compile

asn1_compile_SOURCES = parse.y lex.l main.c hash.c symbol.c gen.c \
	gen_encode.c gen_decode.c gen_free.c gen_length.c gen_copy.c \
	gen_glue.c

libasn1_la_SOURCES = \
	der_get.c \
	der_put.c \
	der_free.c \
	der_length.c \
	der_copy.c \
	timegm.c \
	$(BUILT_SOURCES)

asn1_compile_LDADD = ../roken/libroken.la @LEXLIB@

CLEANFILES = lex.c parse.c parse.h asn1.h $(BUILT_SOURCES) $(foo) asn1_files

incdir = $(includedir)
inc_DATA = asn1.h asn1_err.h
idir = $(top_builddir)/include

all-local: $(inc_DATA)
	@for i in $(inc_DATA); do \
		if cmp -s  $$i $(idir)/$$i 2> /dev/null ; then :; else\
			echo " $(INSTALL_DATA) $$i $(idir)/$$i"; \
			$(INSTALL_DATA) $$i $(idir)/$$i; \
		fi ; \
	done

lex.lo: parse.h

$(foo) asn1.h: asn1_files

asn1_files: asn1_compile $(srcdir)/k5.asn1
	./asn1_compile $(srcdir)/k5.asn1

$(libasn1_la_OBJECTS): asn1.h asn1_err.h

.x.c:
	@cmp -s $< $@ 2> /dev/null || cp $< $@

.et.h:
	$(COMPILE_ET) $<
.et.c:
	$(COMPILE_ET) $<

asn1_err.h: asn1_err.et

asn1_err.c: asn1_err.et
