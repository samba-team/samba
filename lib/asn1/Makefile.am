# $Id$

AUTOMAKE_OPTIONS = no-dependencies

lib_LIBRARIES = libasn1.a

gen_SOURCES = asn1_Realm.c asn1_PrincipalName.c \
	asn1_HostAddress.c asn1_HostAddresses.c asn1_KerberosTime.c \
	asn1_AuthorizationData.c asn1_APOptions.c asn1_TicketFlags.c \
	asn1_KDCOptions.c asn1_LastReq.c asn1_EncryptedData.c \
	asn1_EncryptionKey.c asn1_TransitedEncoding.c asn1_Ticket.c \
	asn1_EncTicketPart.c asn1_Checksum.c asn1_Authenticator.c \
	asn1_PA_DATA.c asn1_KDC_REQ_BODY.c asn1_KDC_REQ.c asn1_AS_REQ.c \
	asn1_TGS_REQ.c asn1_PA_ENC_TS_ENC.c asn1_KDC_REP.c asn1_AS_REP.c \
	asn1_TGS_REP.c asn1_EncKDCRepPart.c asn1_EncASRepPart.c \
	asn1_EncTGSRepPart.c asn1_AP_REQ.c asn1_AP_REP.c \
	asn1_EncAPRepPart.c asn1_KRB_SAFE_BODY.c asn1_KRB_SAFE.c \
	asn1_KRB_PRIV.c asn1_EncKrbPrivPart.c asn1_KRB_CRED.c \
	asn1_KrbCredInfo.c asn1_EncKrbCredPart.c asn1_KRB_ERROR.c

foo=$(gen_SOURCES:%.c=%.x)


libasn1_a_SOURCES = der_get.c der_put.c der_free.c der_length.c der_copy.c \
		$(gen_SOURCES)

noinst_PROGRAMS = asn1_compile

asn1_compile_SOURCES = parse.y lex.l main.c hash.c symbol.c gen.c \
	gen_encode.c gen_decode.c gen_free.c gen_length.c gen_copy.c

asn1_compile_LDADD = @LEXLIB@

CLEANFILES = lex.c parse.c parse.h asn1.h $(gen_SOURCES) $(foo) asn1_files

.SUFFIXES: .x

parse.c: parse.y
	$(YACC) -d $(YFLAGS) $(srcdir)/parse.y
	mv y.tab.c parse.c

parse.h: parse.c
	mv y.tab.h parse.h

lex.c: lex.l
	$(LEX) $(LFLAGS) -t $(srcdir)/lex.l > lex.c

lex.o: parse.h

#libasn1.a: asn1_compile $(libasn1_a_OBJECTS) $(libasn1_a_DEPENDENCIES)
#	./asn1_compile $(srcdir)/k5.asn1
#	o=`sed -e 's/\.c/.o/g' asn1_files`; \
#	$(MAKE) $$o && \
#	rm -f libasn1.a && \
#	$(AR) cru libasn1.a $(libasn1_a_OBJECTS) $(libasn1_a_LIBADD) $$o && \
#	$(RANLIB) libasn1.a

$(foo): asn1_compile $(srcdir)/k5.asn1
	./asn1_compile $(srcdir)/k5.asn1

%.c: %.x
	@cmp -s $< $@ 2> /dev/null || cp $< $@
