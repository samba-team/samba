# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libhx509.la
libhx509_la_LDFLAGS = -version-info 1:0:0

BUILT_SOURCES =				\
	$(gen_files_ocsp:.x=.c)		\
	$(gen_files_pkcs10:.x=.c)	\
	hx509_err.c			\
	hx509_err.h

gen_files_ocsp = 			\
	asn1_OCSPBasicOCSPResponse.x	\
	asn1_OCSPCertID.x		\
	asn1_OCSPCertStatus.x		\
	asn1_OCSPInnerRequest.x		\
	asn1_OCSPKeyHash.x		\
	asn1_OCSPRequest.x		\
	asn1_OCSPResponderID.x		\
	asn1_OCSPResponse.x		\
	asn1_OCSPResponseBytes.x	\
	asn1_OCSPResponseData.x		\
	asn1_OCSPResponseStatus.x	\
	asn1_OCSPSignature.x		\
	asn1_OCSPSingleResponse.x	\
	asn1_OCSPTBSRequest.x		\
	asn1_OCSPVersion.x		\
	asn1_id_kp_OCSPSigning.x	\
	asn1_id_pkix_ocsp.x		\
	asn1_id_pkix_ocsp_basic.x	\
	asn1_id_pkix_ocsp_nonce.x

gen_files_pkcs10 = 			\
	asn1_CertificationRequestInfo.x	\
	asn1_CertificationRequest.x

gen_files_crmf = 			\
	asn1_CRMFRDNSequence.x		\
	asn1_CertReqMessages.x		\
	asn1_CertReqMsg.x		\
	asn1_CertRequest.x		\
	asn1_CertTemplate.x		\
	asn1_Controls.x			\
	asn1_PBMParameter.x		\
	asn1_PKMACValue.x		\
	asn1_POPOPrivKey.x		\
	asn1_POPOSigningKey.x		\
	asn1_POPOSigningKeyInput.x	\
	asn1_ProofOfPossession.x	\
	asn1_SubsequentMessage.x	

dist_libhx509_la_SOURCES = \
	cert.c \
	cms.c \
	collector.c \
	crypto.c \
	error.c \
	file.c \
	hx509-private.h \
	hx509-protos.h \
	hx509.h \
	hx_locl.h \
	keyset.c \
	ks_dir.c \
	ks_file.c \
	ks_mem.c \
	ks_null.c \
	ks_p11.c \
	ks_p12.c \
	lock.c \
	name.c \
	print.c \
	ref/pkcs11.h \
	ref/pkcs11f.h \
	ref/pkcs11t.h \
	ref/pkcs11u.h \
	req.c \
	revoke.c

libhx509_la_LIBADD = \
	$(LIB_des) \
	../asn1/libasn1.la \
	$(LIB_roken) $(LIB_dlopen)

libhx509_la_CPPFLAGS = -I$(srcdir)/ref $(INCLUDE_des)
nodist_libhx509_la_SOURCES = $(BUILT_SOURCES)

$(gen_files_ocsp) ocsp_asn1.h: ocsp_asn1_files
$(gen_files_pkcs10) pkcs10_asn1.h: pkcs10_asn1_files
$(gen_files_crmf) crmf_asn1.h: crmf_asn1_files

ocsp_asn1_files: $(srcdir)/ocsp.asn1
	../asn1/asn1_compile$(EXEEXT) --preserve-binary=OCSPTBSRequest --preserve-binary=OCSPResponseData $(srcdir)/ocsp.asn1 ocsp_asn1 || (rm -f ocsp_asn1_files ; exit 1)

pkcs10_asn1_files: $(srcdir)/pkcs10.asn1
	../asn1/asn1_compile$(EXEEXT) --preserve-binary=CertificationRequestInfo $(srcdir)/pkcs10.asn1 pkcs10_asn1 || (rm -f pkcs10_asn1_files ; exit 1)

crmf_asn1_files: $(srcdir)/crmf.asn1
	../asn1/asn1_compile$(EXEEXT) $(srcdir)/crmf.asn1 crmf_asn1 || (rm -f crmf_asn1_files ; exit 1)


$(libhx509_la_OBJECTS): $(srcdir)/hx509-protos.h $(srcdir)/hx509-private.h

$(srcdir)/hx509-protos.h:
	cd $(srcdir) && perl ../../cf/make-proto.pl -E HX509_LIB_FUNCTION -q -P comment -o hx509-protos.h $(dist_libhx509_la_SOURCES) || rm -f hx509-protos.h

$(srcdir)/hx509-private.h:
	cd $(srcdir) && perl ../../cf/make-proto.pl -q -P comment -p hx509-private.h $(dist_libhx509_la_SOURCES) || rm -f hx509-private.h

dist_include_HEADERS = hx509.h hx509-protos.h
nodist_include_HEADERS = hx509_err.h

SLC = $(top_builddir)/lib/sl/slc

bin_PROGRAMS = hxtool

hxtool-commands.c hxtool-commands.h: hxtool-commands.in $(SLC)
	$(SLC) $(srcdir)/hxtool-commands.in

dist_hxtool_SOURCES = hxtool.c
nodist_hxtool_SOURCES = hxtool-commands.c hxtool-commands.h

$(hxtool_OBJECTS): hxtool-commands.h

hxtool_CPPFLAGS = $(INCLUDE_des)
hxtool_LDADD = libhx509.la $(LIB_roken) ../sl/libsl.la $(LIB_des)
hxtool_LDFLAGS = -pthread

CLEANFILES = $(BUILT_SOURCES) \
	$(gen_files_ocsp) ocsp_asn1_files ocsp_asn1.h \
	$(gen_files_pkcs10) pkcs10_asn1_files pkcs10_asn1.h \
	$(gen_files_crmf) crmf_asn1_files crmf_asn1.h \
	$(TESTS) \
	hxtool-commands.c hxtool-commands.h *.tmp \
	request.out \
	sd.data sd.data.out \
	ev.data ev.data.out \
	random-data


#
# regression tests
#

check_SCRIPTS = $(SCRIPT_TESTS)
check_PROGRAMS = $(PROGRAM_TESTS)

LDADD = libhx509.la

TESTS = $(SCRIPT_TESTS) $(PROGRAM_TESTS)

PROGRAM_TESTS = 		\
	test_name

SCRIPT_TESTS = 			\
	test_chain		\
	test_cms		\
	test_crypto		\
	test_nist		\
	test_nist_cert		\
	test_nist_pkcs12	\
	test_req		\
	test_query

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g'

test_chain: test_chain.in Makefile
	$(do_subst) < $(srcdir)/test_chain.in > test_chain.tmp
	chmod +x test_chain.tmp
	mv test_chain.tmp test_chain

test_cms: test_cms.in Makefile
	$(do_subst) < $(srcdir)/test_cms.in > test_cms.tmp
	chmod +x test_cms.tmp
	mv test_cms.tmp test_cms

test_crypto: test_crypto.in Makefile
	$(do_subst) < $(srcdir)/test_crypto.in > test_crypto.tmp
	chmod +x test_crypto.tmp
	mv test_crypto.tmp test_crypto

test_nist: test_nist.in Makefile
	$(do_subst) < $(srcdir)/test_nist.in > test_nist.tmp
	chmod +x test_nist.tmp
	mv test_nist.tmp test_nist

test_nist_cert: test_nist_cert.in Makefile
	$(do_subst) < $(srcdir)/test_nist_cert.in > test_nist_cert.tmp
	chmod +x test_nist_cert.tmp
	mv test_nist_cert.tmp test_nist_cert

test_nist_pkcs12: test_nist_pkcs12.in Makefile
	$(do_subst) < $(srcdir)/test_nist_pkcs12.in > test_nist_pkcs12.tmp
	chmod +x test_nist_pkcs12.tmp
	mv test_nist_pkcs12.tmp test_nist_pkcs12

test_req: test_req.in Makefile
	$(do_subst) < $(srcdir)/test_req.in > test_req.tmp
	chmod +x test_req.tmp
	mv test_req.tmp test_req

test_query: test_query.in Makefile
	$(do_subst) < $(srcdir)/test_query.in > test_query.tmp
	chmod +x test_query.tmp
	mv test_query.tmp test_query

EXTRA_DIST = 
	hx509_err.et \
	pkcs10.asn1 \
	ocsp.asn1 \
	crmf.asn1 \
	hxtool-commands.in \
	test_chain.in \
	test_cms.in \
	test_crypto.in \
	test_nist.in \
	test_nist_cert.in \
	test_nist_pkcs12.in \
	test_req.in \
	test_query.in \
	data/bleichenbacher-bad.pem \
	data/bleichenbacher-good.pem \
	data/bleichenbacher-sf-pad-correct.pem \
	data/ca.crt \
	data/ca.key \
	data/crl1.crl \
	data/crl1.der \
	data/gen-req.sh \
	data/index.txt \
	data/index.txt.attr \
	data/kdc.crt \
	data/kdc.key \
	data/key.der \
	data/nist-data \
	data/no-proxy-test.crt \
	data/no-proxy-test.key \
	data/ocsp-req1.der \
	data/ocsp-req2.der \
	data/ocsp-resp1-2.der \
	data/ocsp-resp1-3.der \
	data/ocsp-resp1-ca.der \
	data/ocsp-resp1-keyhash.der \
	data/ocsp-resp1-ocsp-no-cert.der \
	data/ocsp-resp1-ocsp.der \
	data/ocsp-resp1.der \
	data/ocsp-resp2.der \
	data/ocsp-responder.crt \
	data/ocsp-responder.key \
	data/openssl.cnf \
	data/pkinit-pw.key \
	data/pkinit.crt \
	data/pkinit.key \
	data/proxy-level-test.crt \
	data/proxy-level-test.key \
	data/proxy-test.crt \
	data/proxy-test.key \
	data/proxy10-child-test.crt \
	data/proxy10-child-test.key \
	data/proxy10-test.crt \
	data/proxy10-test.key \
	data/revoke.crt \
	data/revoke.key \
	data/serial \
	data/sf-class2-root.pem \
	data/static-file \
	data/sub-ca.crt \
	data/sub-ca.key \
	data/sub-cert.crt \
	data/sub-cert.key \
	data/sub-cert.p12 \
	data/test-ds-only.crt \
	data/test-ds-only.key \
	data/test-enveloped-aes-128 \
	data/test-enveloped-aes-256 \
	data/test-enveloped-des \
	data/test-enveloped-des-ede3 \
	data/test-enveloped-rc2-128 \
	data/test-enveloped-rc2-40 \
	data/test-enveloped-rc2-64 \
	data/test-ke-only.crt \
	data/test-ke-only.key \
	data/test-pw.key \
	data/test-signed-data \
	data/test-signed-data-noattr \
	data/test-signed-data-noattr-nocerts \
	data/test.combined.crt \
	data/test.crt \
	data/test.key \
	data/test.p12 \
	data/yutaka-pad-broken-ca.pem \
	data/yutaka-pad-broken-cert.pem \
	data/yutaka-pad-ok-ca.pem \
	data/yutaka-pad-ok-cert.pem \
	data/yutaka-pad.key
