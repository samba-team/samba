# $Id$

include $(top_srcdir)/Makefile.am.common

SUBDIRS = kadm5 hcrypto gssapi

noinst_PROGRAMS = bits make_crypto
CHECK_LOCAL = no-check-local

AM_CPPFLAGS += -DHOST=\"$(CANONICAL_HOST)\"

nodist_include_HEADERS = krb5-types.h
nodist_noinst_HEADERS = crypto-headers.h

krb5-types.h: bits$(EXEEXT)
	./bits$(EXEEXT) krb5-types.h

crypto-headers.h: make_crypto$(EXEEXT)
	./make_crypto$(EXEEXT) crypto-headers.h

CLEANFILES =			\
	asn1.h			\
	asn1_err.h		\
	base64.h		\
	cms_asn1.h 		\
	com_err.h		\
	com_right.h		\
	crypto-headers.h	\
	der-protos.h 		\
	der.h			\
	digest_asn1.h 		\
	editline.h		\
	err.h			\
	getarg.h		\
	glob.h			\
	gssapi.h		\
	hdb-protos.h		\
	hdb.h			\
	hdb_asn1.h		\
	hdb_err.h		\
	heim_asn1.h		\
	heim_err.h		\
	heim_threads.h		\
	heimntlm-protos.h	\
	heimntlm.h		\
	hex.h			\
	hx509-protos.h		\
	hx509.h			\
	hx509_err.h		\
	k524_err.h		\
	kafs.h			\
	kdc-protos.h		\
	kdc.h			\
	krb5-private.h		\
	krb5-protos.h		\
	krb5-types.h		\
	krb5.h			\
	krb5_asn1.h		\
	krb5_ccapi.h		\
	krb5_err.h		\
	krb_err.h		\
	kx509_asn1.h		\
	kx509_err.h		\
	locate_plugin.h		\
	otp.h			\
	parse_bytes.h		\
	parse_time.h		\
	parse_units.h		\
	pkcs12_asn1.h		\
	pkcs8_asn1.h		\
	pkcs9_asn1.h		\
	pkinit_asn1.h		\
	resolve.h		\
	rfc2459_asn1.h		\
	roken-common.h		\
	roken.h			\
	rtbl.h			\
	sl.h			\
	test-mem.h		\
	vers.h			\
	vis.h			\
	wind.h			\
	wind_err.h		\
	windc_plugin.h		\
	xdbm.h

DISTCLEANFILES = 	\
	version.h	\
	version.h.in
