# $Id$

include $(top_srcdir)/Makefile.am.common

WFLAGS += $(WFLAGS_ENUM_CONV)

AM_CPPFLAGS += $(INCLUDE_libintl) $(INCLUDE_openssl_crypto) -I$(srcdir)/../lib/krb5

lib_LTLIBRARIES = ipc_csr_authorizer.la \
		  negotiate_token_validator.la \
		  libkdc.la

if HAVE_CJWT
lib_LTLIBRARIES += cjwt_token_validator.la
endif
if OPENLDAP
lib_LTLIBRARIES += altsecid_gss_preauth_authorizer.la
endif


bin_PROGRAMS = string2key

sbin_PROGRAMS = kstash

libexec_PROGRAMS = hprop hpropd kdc digest-service \
		   test_token_validator test_csr_authorizer test_kdc_ca

noinst_PROGRAMS = kdc-replay kdc-tester

man_MANS = bx509d.8 httpkadmind.8 kdc.8 kstash.8 hprop.8 hpropd.8 string2key.8

hprop_SOURCES = hprop.c mit_dump.c hprop.h
hpropd_SOURCES = hpropd.c hprop.h

kstash_SOURCES = kstash.c headers.h

string2key_SOURCES = string2key.c headers.h

if HAVE_MICROHTTPD
bx509d_SOURCES = bx509d.c
bx509d_AM_CPPFLAGS = $(AM_CPPFLAGS) $(MICROHTTPD_CFLAGS)
bx509d_LDADD =	-ldl \
                 $(top_builddir)/lib/hdb/libhdb.la \
		 libkdc.la \
		 $(MICROHTTPD_LIBS) \
		 $(LIB_roken) \
		 $(LIB_heimbase) \
		 $(LIB_hcrypto) \
		 $(top_builddir)/lib/sl/libsl.la \
		 $(top_builddir)/lib/asn1/libasn1.la \
		 $(top_builddir)/lib/krb5/libkrb5.la \
		 $(top_builddir)/lib/hx509/libhx509.la \
		 $(top_builddir)/lib/gssapi/libgssapi.la
libexec_PROGRAMS += bx509d

httpkadmind_SOURCES = httpkadmind.c
httpkadmind_AM_CPPFLAGS = $(AM_CPPFLAGS) $(MICROHTTPD_CFLAGS)
httpkadmind_LDADD =	-ldl \
		 $(top_builddir)/lib/hdb/libhdb.la \
		 $(top_builddir)/lib/kadm5/libkadm5clnt.la \
		 $(top_builddir)/lib/kadm5/libkadm5srv.la \
		 libkdc.la \
		 $(MICROHTTPD_LIBS) \
		 $(LIB_roken) \
		 $(LIB_heimbase) \
		 $(LIB_hcrypto) \
		 $(top_builddir)/lib/sl/libsl.la \
		 $(top_builddir)/lib/asn1/libasn1.la \
		 $(top_builddir)/lib/krb5/libkrb5.la \
		 $(top_builddir)/lib/hx509/libhx509.la \
		 $(top_builddir)/lib/gssapi/libgssapi.la
libexec_PROGRAMS += httpkadmind
endif

digest_service_SOURCES = \
	digest-service.c

kdc_SOURCES = connect.c	\
	config.c	\
	announce.c	\
	main.c

kdc_tester_SOURCES = \
	config.c	\
	kdc-tester.c

test_token_validator_SOURCES = test_token_validator.c
test_csr_authorizer_SOURCES = test_csr_authorizer.c
test_kdc_ca_SOURCES = test_kdc_ca.c

# Token plugins (for bx509d)
if HAVE_CJWT
cjwt_token_validator_la_SOURCES = cjwt_token_validator.c
cjwt_token_validator_la_CFLAGS = $(CJSON_CFLAGS) $(CJWT_CFLAGS)
cjwt_token_validator_la_LDFLAGS = -module $(CJSON_LIBS) $(CJWT_LIBS)
endif

negotiate_token_validator_la_SOURCES = negotiate_token_validator.c
negotiate_token_validator_la_LDFLAGS = -module $(LIB_gssapi)
# CSR Authorizer plugins (for kdc/kx509 and bx509d)
ipc_csr_authorizer_la_SOURCES = ipc_csr_authorizer.c
ipc_csr_authorizer_la_LDFLAGS = -module	\
				$(top_builddir)/lib/krb5/libkrb5.la \
				$(top_builddir)/lib/hx509/libhx509.la \
				$(top_builddir)/lib/ipc/libheim-ipcc.la \
				$(top_builddir)/lib/roken/libroken.la

# GSS-API authorization plugins
if OPENLDAP
altsecid_gss_preauth_authorizer_la_SOURCES = altsecid_gss_preauth_authorizer.c
altsecid_gss_preauth_authorizer_la_LDFLAGS = -module \
					     $(top_builddir)/lib/gssapi/libgssapi.la \
					     $(top_builddir)/lib/krb5/libkrb5.la \
					     $(LIB_openldap)
endif

libkdc_la_CPPFLAGS = -DBUILD_KDC_LIB $(AM_CPPFLAGS)

libkdc_la_SOURCES = 		\
	default_config.c 	\
	ca.c			\
	set_dbinfo.c	 	\
	digest.c		\
	fast.c			\
	kdc_locl.h		\
	kerberos5.c		\
	krb5tgs.c		\
	pkinit.c		\
	pkinit-ec.c		\
	mssfu.c			\
	log.c			\
	misc.c			\
	kx509.c			\
	token_validator.c	\
	csr_authorizer.c	\
	process.c		\
	kdc-plugin.c		\
	gss_preauth.c

KDC_PROTOS = $(srcdir)/kdc-protos.h $(srcdir)/kdc-private.h

ALL_OBJECTS  = $(kdc_OBJECTS)
ALL_OBJECTS += $(kdc_replay_OBJECTS)
ALL_OBJECTS += $(kdc_tester_OBJECTS)
ALL_OBJECTS += $(test_token_validator_OBJECTS)
ALL_OBJECTS += $(test_csr_authorizer_OBJECTS)
ALL_OBJECTS += $(test_kdc_ca_OBJECTS)
ALL_OBJECTS += $(libkdc_la_OBJECTS)
ALL_OBJECTS += $(string2key_OBJECTS)
ALL_OBJECTS += $(kstash_OBJECTS)
ALL_OBJECTS += $(hprop_OBJECTS)
ALL_OBJECTS += $(hpropd_OBJECTS)
ALL_OBJECTS += $(digest_service_OBJECTS)
ALL_OBJECTS += $(bx509d_OBJECTS)
ALL_OBJECTS += $(httpkadmind_OBJECTS)
ALL_OBJECTS += $(cjwt_token_validator_la_OBJECTS)
ALL_OBJECTS += $(test_token_validator_OBJECTS)
ALL_OBJECTS += $(test_csr_authorizer_OBJECTS)
ALL_OBJECTS += $(test_kdc_ca_OBJECTS)
ALL_OBJECTS += $(ipc_csr_authorizer_la_OBJECTS)
ALL_OBJECTS += $(negotiate_token_validator_la_OBJECTS)

$(ALL_OBJECTS): $(KDC_PROTOS)

libkdc_la_LDFLAGS = -version-info 2:0:0

if versionscript
libkdc_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-script.map
endif

$(libkdc_la_OBJECTS): $(srcdir)/version-script.map

$(srcdir)/kdc-protos.h: $(libkdc_la_SOURCES)
	cd $(srcdir) && perl ../cf/make-proto.pl -E KDC_LIB -q -P comment -o kdc-protos.h $(libkdc_la_SOURCES) || rm -f kdc-protos.h

$(srcdir)/kdc-private.h: $(libkdc_la_SOURCES)
	cd $(srcdir) && perl ../cf/make-proto.pl -q -P comment -p kdc-private.h $(libkdc_la_SOURCES) || rm -f kdc-private.h


hprop_LDADD = \
	$(top_builddir)/lib/hdb/libhdb.la \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(LIB_kdb)  \
	$(LIB_hcrypto) \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_roken) \
	$(DB3LIB) $(DB1LIB) $(LMDBLIB) $(NDBMLIB)

hpropd_LDADD = \
	$(top_builddir)/lib/hdb/libhdb.la \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(LIB_kdb)  \
	$(LIB_hcrypto) \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_roken) \
	$(DB3LIB) $(DB1LIB) $(LMDBLIB) $(NDBMLIB)

if PKINIT
LIB_pkinit = $(top_builddir)/lib/hx509/libhx509.la
endif

libkdc_la_LIBADD = \
	$(LIB_pkinit) \
	$(top_builddir)/lib/hdb/libhdb.la \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(top_builddir)/lib/gssapi/libgssapi.la \
	$(top_builddir)/lib/gss_preauth/libgss_preauth.la \
	$(LIB_kdb)  \
	$(top_builddir)/lib/ntlm/libheimntlm.la \
	$(LIB_hcrypto) \
	$(LIB_openssl_crypto) \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_roken) \
	$(DB3LIB) $(DB1LIB) $(LMDBLIB) $(NDBMLIB)

LDADD = $(top_builddir)/lib/hdb/libhdb.la \
	$(top_builddir)/lib/krb5/libkrb5.la \
	$(LIB_hcrypto) \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_roken) \
	$(DB3LIB) $(DB1LIB) $(LMDBLIB) $(NDBMLIB)

kdc_LDADD = libkdc.la $(LDADD) $(LIB_pidfile) $(CAPNG_LIBS)

if FRAMEWORK_SECURITY
kdc_LDFLAGS = -framework SystemConfiguration -framework CoreFoundation
endif
kdc_CFLAGS = $(CAPNG_CFLAGS)

digest_service_LDADD = \
	libkdc.la \
	$(top_builddir)/lib/ntlm/libheimntlm.la \
	$(top_builddir)/lib/ipc/libheim-ipcs.la \
	$(LDADD) $(LIB_pidfile)
kdc_replay_LDADD = libkdc.la $(LDADD) $(LIB_pidfile)
kdc_tester_LDADD = libkdc.la $(LDADD) $(LIB_pidfile) $(LIB_heimbase)
test_token_validator_LDADD = libkdc.la $(LDADD) $(LIB_pidfile) $(LIB_heimbase) $(LIB_gssapi)
test_csr_authorizer_LDADD = libkdc.la \
			    $(top_builddir)/lib/hx509/libhx509.la \
			    $(LDADD) \
			    $(LIB_pidfile) \
			    $(LIB_heimbase) \
			    $(top_builddir)/lib/ipc/libheim-ipcs.la
test_kdc_ca_LDADD = libkdc.la $(top_builddir)/lib/hx509/libhx509.la $(LDADD) $(LIB_pidfile) $(LIB_heimbase)

include_HEADERS = kdc.h $(srcdir)/kdc-protos.h

noinst_HEADERS = $(srcdir)/kdc-private.h

krb5dir = $(includedir)/krb5
krb5_HEADERS = kdc-audit.h kdc-plugin.h kdc-accessors.h token_validator_plugin.h csr_authorizer_plugin.h gss_preauth_authorizer_plugin.h

build_HEADERZ = $(krb5_HEADERS) # XXX

EXTRA_DIST = \
	hprop-version.rc \
	hpropd-version.rc \
	kdc-version.rc \
	kstash-version.rc \
	libkdc-version.rc \
	string2key-version.rc \
	libkdc-exports.def \
	NTMakefile $(man_MANS) version-script.map
