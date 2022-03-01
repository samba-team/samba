# $Id$

include $(top_srcdir)/Makefile.am.common

SUBDIRS = kadm5 hcrypto gssapi

noinst_PROGRAMS = bits
CHECK_LOCAL = no-check-local

AM_CPPFLAGS += -DHOST=\"$(CANONICAL_HOST)\"

nodist_include_HEADERS = krb5-types.h

noinst_HEADERS = heimqueue.h heim_threads.h crypto-headers.h

EXTRA_DIST = NTMakefile krb5-types.cross config.h.w32

if !CROSS_COMPILE

krb5-types.h: bits$(EXEEXT)
	./bits$(EXEEXT) krb5-types.h

else

krb5-types.h: krb5-types.cross
	cp $(srcdir)/krb5-types.cross krb5-types.h

endif

CLEANFILES =			\
	an2ln_plugin.h		\
	asn1-common.h		\
	asn1-template.h		\
	asn1.h			\
	asn1_err.h		\
	base64.h		\
	ccache_plugin.h		\
	cms_asn1.h 		\
	cms_template_asn1.h 	\
	com_err.h		\
	com_right.h		\
	common_plugin.h		\
	crmf_asn1.h		\
	crmf_template_asn1.h	\
	db_plugin.h		\
	der-private.h 		\
	der-protos.h 		\
	der.h			\
	digest_asn1.h 		\
	digest_template_asn1.h 	\
	editline.h		\
	err.h			\
	getarg.h		\
	glob.h			\
	gss-preauth-protos.h	\
	gss-preauth-private.h	\
	gssapi.h		\
	gssapi_asn1.h		\
	gssapi_mech.h		\
	gssapi/gssapi_preauth.h	\
	hdb-private.h		\
	hdb-protos.h		\
	hdb.h			\
	hdb_asn1.h		\
	hdb_err.h		\
	heim-ipc.h		\
	heim_asn1.h		\
	heim_err.h		\
	heimbase.h		\
	heimbase-svc.h		\
	heimbase-protos.h	\
	heimntlm-protos.h	\
	heimntlm.h		\
	hex.h			\
	hx509-private.h		\
	hx509-protos.h		\
	hx509.h			\
	hx509_err.h		\
	k524_err.h		\
	k5e1_err.h		\
	kafs.h			\
	kcm-protos.h		\
	kdc-private.h		\
	kdc-protos.h		\
	kdc.h			\
	krb5-private.h		\
	krb5-protos.h		\
	krb5-types.h		\
	krb5.h			\
	krb5_asn1.h		\
	krb5_template_asn1.h	\
	krb5_ccapi.h		\
	krb5_err.h		\
	krb_err.h		\
	kuserok_plugin.h	\
	kx509_asn1.h		\
	kx509_template_asn1.h	\
	kx509_err.h		\
	locate_plugin.h		\
	login-protos.h		\
	ntlm_err.h		\
	ocsp_asn1.h		\
	ocsp_template_asn1.h	\
	otp.h			\
	parse_bytes.h		\
	parse_time.h		\
	parse_units.h		\
	pkcs10_asn1.h		\
	pkcs10_template_asn1.h	\
	pkcs12_asn1.h		\
	pkcs12_template_asn1.h	\
	pkcs8_asn1.h		\
	pkcs8_template_asn1.h	\
	pkcs9_asn1.h		\
	pkcs9_template_asn1.h	\
	pkinit_asn1.h		\
	pkinit_template_asn1.h	\
	resolve.h		\
	rfc2459_asn1.h		\
	rfc2459_template_asn1.h	\
	rfc4108_asn1.h		\
	rfc4108_template_asn1.h	\
	roken-common.h		\
	roken.h			\
	rtbl.h			\
	send_to_kdc_plugin.h	\
	sl.h			\
	sqlite3.h		\
	sqlite3ext.h		\
	test-mem.h		\
	vers.h			\
	vis.h			\
	wind.h			\
	wind_err.h		\
	kdc-plugin.h		\
	kdc-accessors.h		\
	kdc-audit.h		\
	csr_authorizer_plugin.h	\
	gss_preauth_authorizer_plugin.h	\
	token_validator_plugin.h	\
	xdbm.h			\
	x25519_ref10.h		\
	x690sample_asn1.h	\
	x690sample_template_asn1.h

DISTCLEANFILES = 	\
	version.h	\
	version.h.in
