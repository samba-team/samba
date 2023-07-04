# $Id$

include $(top_srcdir)/Makefile.am.common

WFLAGS += $(WFLAGS_ENUM_CONV)

AM_YFLAGS = -d -o asn1parse.c -t

AM_CPPFLAGS += $(ROKEN_RENAME) -I$(top_builddir)/include -I$(top_srcdir)/lib/base

man_MANS = asn1_print.1 asn1_compile.1

lib_LTLIBRARIES = libasn1.la libasn1template.la
libasn1_la_LDFLAGS = -version-info 8:0:0
libasn1template_la_LDFLAGS = -version-info 8:0:0

noinst_LTLIBRARIES = libasn1base.la

if versionscript
libasn1_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-script.map
libasn1template_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-script.map
endif


libasn1_la_LIBADD = \
	libasn1base.la \
	@LIB_com_err@ \
	$(LIBADD_roken)

libasn1template_la_LIBADD = \
	libasn1base.la \
	@LIB_com_err@ \
	$(LIBADD_roken)

BUILT_SOURCES =			\
	$(gen_files_rfc2459)	\
	$(gen_files_rfc4108)	\
	$(gen_files_cms)	\
	$(gen_files_krb5)	\
	$(gen_files_ocsp)	\
	$(gen_files_pkinit)	\
	$(gen_files_pkcs8)	\
	$(gen_files_pkcs9)	\
	$(gen_files_pkcs10)	\
	$(gen_files_pkcs12)	\
	$(gen_files_digest)	\
	$(gen_files_kx509)

BUILT_TEMPLATE_SOURCES =		\
	$(gen_files_rfc2459_template)	\
	$(gen_files_rfc4108_template)	\
	$(gen_files_cms_template)	\
	$(gen_files_krb5_template)	\
	$(gen_files_ocsp_template)	\
	$(gen_files_pkinit_template)	\
	$(gen_files_pkcs8_template)	\
	$(gen_files_pkcs9_template)	\
	$(gen_files_pkcs10_template)	\
	$(gen_files_pkcs12_template)	\
	$(gen_files_digest_template)	\
	$(gen_files_kx509_template)

gen_files_krb5 = asn1_krb5_asn1.c
gen_files_krb5_template = asn1_krb5_template_asn1.c
gen_files_cms = asn1_cms_asn1.c
gen_files_cms_template = asn1_cms_template_asn1.c
gen_files_crmf = asn1_crmf_asn1.c
gen_files_crmf_template = asn1_crmf_template_asn1.c
gen_files_rfc2459 = asn1_rfc2459_asn1.c
gen_files_rfc2459_template = asn1_rfc2459_template_asn1.c
gen_files_rfc4108 = asn1_rfc4108_asn1.c
gen_files_rfc4108_template = asn1_rfc4108_template_asn1.c
gen_files_ocsp = asn1_ocsp_asn1.c
gen_files_ocsp_template = asn1_ocsp_template_asn1.c
gen_files_pkinit = asn1_pkinit_asn1.c
gen_files_pkinit_template = asn1_pkinit_template_asn1.c
gen_files_pkcs10 = asn1_pkcs10_asn1.c
gen_files_pkcs10_template = asn1_pkcs10_template_asn1.c
gen_files_pkcs12 = asn1_pkcs12_asn1.c
gen_files_pkcs12_template = asn1_pkcs12_template_asn1.c
gen_files_pkcs8 = asn1_pkcs8_asn1.c
gen_files_pkcs8_template = asn1_pkcs8_template_asn1.c
gen_files_pkcs9 = asn1_pkcs9_asn1.c
gen_files_pkcs9_template = asn1_pkcs9_template_asn1.c
gen_files_test = asn1_test_asn1.c
gen_files_test_template = asn1_test_template_asn1.c
gen_files_digest = asn1_digest_asn1.c
gen_files_digest_template = asn1_digest_template_asn1.c
gen_files_kx509 = asn1_kx509_asn1.c
gen_files_kx509_template = asn1_kx509_template_asn1.c
gen_files_x690sample = asn1_x690sample_asn1.c
gen_files_x690sample_template = asn1_x690sample_template_asn1.c

oid_resolution.lo: $(BUILT_SOURCES)

noinst_PROGRAMS = asn1_gen

bin_PROGRAMS = asn1_compile asn1_print

TESTS = check-der check-gen check-gen-template check-timegm check-ber check-template
check_PROGRAMS = $(TESTS)

asn1_gen_SOURCES = asn1_gen.c
asn1_print_SOURCES = asn1_print.c
asn1_print_SOURCES += $(gen_files_x690sample_template)
asn1_print_CPPFLAGS = -DASN1_PRINT_SUPPORTED
check_der_SOURCES = check-der.c check-common.c check-common.h

check_template_SOURCES = check-template.c check-common.c check-common.h
nodist_check_template_SOURCES = $(gen_files_test_template)

check_gen_template_CPPFLAGS = -DASN1_IOS_SUPPORTED
dist_check_gen_template_SOURCES = check-gen.c check-common.c check-common.h
nodist_check_gen_template_SOURCES =	$(gen_files_test_template) \
					$(gen_files_x690sample_template)

dist_check_gen_SOURCES = check-gen.c check-common.c check-common.h
nodist_check_gen_SOURCES = $(gen_files_test) $(gen_files_x690sample)

build_HEADERZ = asn1-template.h

asn1_compile_SOURCES = 				\
	asn1parse.y				\
	der.h					\
	gen.c					\
	gen_copy.c				\
	gen_decode.c				\
	gen_encode.c				\
	gen_print.c				\
	gen_free.c				\
	gen_glue.c				\
	gen_length.c				\
	gen_locl.h				\
	gen_seq.c				\
	gen_template.c				\
	hash.c					\
	hash.h					\
	lex.l					\
	lex.h					\
	main.c					\
	asn1-template.h				\
	symbol.c				\
	symbol.h

dist_libasn1base_la_SOURCES =			\
	der_locl.h 				\
	der.c					\
	der.h					\
	der_get.c				\
	der_put.c				\
	der_free.c				\
	der_print.c				\
	der_length.c				\
	der_copy.c				\
	der_cmp.c				\
	der_format.c				\
	fuzzer.c				\
	heim_asn1.h				\
	extra.c					\
	roken_rename.h				\
	template.c				\
	timegm.c

dist_libasn1_la_SOURCES = oid_resolution.c
dist_libasn1template_la_SOURCES = oid_resolution.c

nodist_libasn1base_la_SOURCES = 	\
	asn1_err.h			\
	asn1_err.c

nodist_libasn1_la_SOURCES = $(BUILT_SOURCES)

if !ASN1_TEMPLATING
nodist_libasn1template_la_SOURCES = $(BUILT_TEMPLATE_SOURCES)
else
nodist_libasn1template_la_SOURCES = $(BUILT_SOURCES)
endif

asn1_compile_LDADD = \
	$(LIB_roken) $(LEXLIB)

check_der_LDADD = \
	libasn1.la \
	$(LIB_roken)

check_template_LDADD = $(check_der_LDADD)
asn1_print_LDADD = libasn1template.la $(LIB_roken) $(LIB_com_err)
asn1_gen_LDADD = $(check_der_LDADD)
check_timegm_LDADD = $(check_der_LDADD)

check_gen_template_LDADD = \
	libasn1template.la \
	$(LIB_roken)

check_gen_LDADD = \
	libasn1template.la \
	$(LIB_roken)

check_ber_LDADD = $(check_gen_LDADD)

CLEANFILES = \
	$(BUILT_SOURCES) \
	$(gen_files_rfc2459) \
	$(gen_files_rfc2459_template) \
	$(gen_files_rfc4108) \
	$(gen_files_rfc4108_template) \
	$(gen_files_cms) \
	$(gen_files_cms_template) \
	$(gen_files_krb5) \
	$(gen_files_krb5_template) \
	$(gen_files_ocsp) \
	$(gen_files_ocsp_template) \
	$(gen_files_pkinit) \
	$(gen_files_pkinit_template) \
	$(gen_files_pkcs8) \
	$(gen_files_pkcs8_template) \
	$(gen_files_pkcs9) \
	$(gen_files_pkcs9_template) \
	$(gen_files_pkcs10) \
	$(gen_files_pkcs10_template) \
	$(gen_files_pkcs12) \
	$(gen_files_pkcs12_template) \
	$(gen_files_digest) \
	$(gen_files_digest_template) \
	$(gen_files_kx509) \
	$(gen_files_kx509_template) \
	$(gen_files_x690sample) \
	$(gen_files_x690sample_template) \
	$(gen_files_test) \
	$(gen_files_test_template) \
	$(nodist_check_gen_SOURCES) \
	asn1parse.c asn1parse.h lex.c \
	asn1_err.c asn1_err.h \
	rfc2459_asn1_files rfc2459_asn1*.h \
	rfc2459_template_asn1_files rfc2459_template_asn1*.h \
	rfc4108_asn1_files rfc4108_asn1*.h \
	rfc4108_template_asn1_files rfc4108_template_asn1*.h \
	cms_asn1_files cms_asn1*.h \
	cms_template_asn1_files cms_template_asn1* \
	crmf_asn1_files crmf_asn1* \
	crmf_template_asn1_files crmf_template_asn1* \
	krb5_asn1_files krb5_asn1* \
	krb5_template_asn1_files krb5_template_asn1* \
	ocsp_asn1_files ocsp_asn1* \
	ocsp_template_asn1_files ocsp_template_asn1* \
	pkinit_asn1_files pkinit_asn1* \
	pkinit_template_asn1_files pkinit_template_asn1* \
	pkcs8_asn1_files pkcs8_asn1* \
	pkcs8_template_asn1_files pkcs8_template_asn1* \
	pkcs9_asn1_files pkcs9_asn1* \
	pkcs9_template_asn1_files pkcs9_template_asn1* \
	pkcs10_asn1_files pkcs10_asn1* \
	pkcs10_template_asn1_files pkcs10_template_asn1* \
	pkcs12_asn1_files pkcs12_asn1* \
	pkcs12_template_asn1_files pkcs12_template_asn1* \
	digest_asn1_files digest_asn1* \
	digest_template_asn1_files digest_template_asn1* \
	kx509_asn1_files kx509_asn1* \
	kx509_template_asn1_files kx509_template_asn1* \
	x690sample_asn1_files x690sample_asn1* \
	x690sample_template_asn1_files x690sample_template_asn1* \
	test_asn1_files test_asn1* \
	test_template_asn1_files test_template_asn1* \
	asn1_*_asn1.c *_asn1.json *_asn1_syms.c *_asn1_oids.c

dist_include_HEADERS = der.h heim_asn1.h
dist_include_HEADERS += $(srcdir)/der-protos.h $(srcdir)/der-private.h
dist_include_HEADERS += asn1-common.h

nodist_include_HEADERS = asn1_err.h
nodist_include_HEADERS += krb5_asn1.h
nodist_include_HEADERS += krb5_template_asn1.h
nodist_include_HEADERS += pkinit_asn1.h
nodist_include_HEADERS += pkinit_template_asn1.h
nodist_include_HEADERS += cms_asn1.h
nodist_include_HEADERS += cms_template_asn1.h
nodist_include_HEADERS += crmf_asn1.h
nodist_include_HEADERS += crmf_template_asn1.h
nodist_include_HEADERS += rfc2459_asn1.h
nodist_include_HEADERS += rfc2459_template_asn1.h
nodist_include_HEADERS += rfc4108_asn1.h
nodist_include_HEADERS += rfc4108_template_asn1.h
nodist_include_HEADERS += ocsp_asn1.h
nodist_include_HEADERS += ocsp_template_asn1.h
nodist_include_HEADERS += pkcs8_asn1.h
nodist_include_HEADERS += pkcs8_template_asn1.h
nodist_include_HEADERS += pkcs9_asn1.h
nodist_include_HEADERS += pkcs9_template_asn1.h
nodist_include_HEADERS += pkcs10_asn1.h
nodist_include_HEADERS += pkcs10_template_asn1.h
nodist_include_HEADERS += pkcs12_asn1.h
nodist_include_HEADERS += pkcs12_template_asn1.h
nodist_include_HEADERS += digest_asn1.h
nodist_include_HEADERS += digest_template_asn1.h
nodist_include_HEADERS += kx509_asn1.h
nodist_include_HEADERS += kx509_template_asn1.h
nodist_include_HEADERS += x690sample_asn1.h
nodist_include_HEADERS += x690sample_template_asn1.h

priv_headers  = krb5_asn1-priv.h
priv_headers += krb5_template_asn1-priv.h
priv_headers += pkinit_asn1-priv.h
priv_headers += pkinit_template_asn1-priv.h
priv_headers += cms_asn1-priv.h
priv_headers += cms_template_asn1-priv.h
priv_headers += crmf_asn1-priv.h
priv_headers += crmf_template_asn1-priv.h
priv_headers += rfc2459_asn1-priv.h
priv_headers += rfc2459_template_asn1-priv.h
priv_headers += rfc4108_asn1-priv.h
priv_headers += rfc4108_template_asn1-priv.h
priv_headers += ocsp_asn1-priv.h
priv_headers += ocsp_template_asn1-priv.h
priv_headers += pkcs8_asn1-priv.h
priv_headers += pkcs8_template_asn1-priv.h
priv_headers += pkcs9_asn1-priv.h
priv_headers += pkcs9_template_asn1-priv.h
priv_headers += pkcs10_asn1-priv.h
priv_headers += pkcs10_template_asn1-priv.h
priv_headers += pkcs12_asn1-priv.h
priv_headers += pkcs12_template_asn1-priv.h
priv_headers += digest_asn1-priv.h
priv_headers += digest_template_asn1-priv.h
priv_headers += kx509_asn1-priv.h
priv_headers += kx509_template_asn1-priv.h
priv_headers += x690sample_asn1-priv.h
priv_headers += x690sample_template_asn1-priv.h
priv_headers += test_asn1.h test_asn1-priv.h
priv_headers += test_template_asn1.h test_template_asn1-priv.h



$(asn1_compile_OBJECTS): asn1parse.h asn1parse.c $(srcdir)/der-protos.h $(srcdir)/der-private.h
$(libasn1_la_OBJECTS): $(nodist_include_HEADERS) $(priv_headers) asn1_err.h $(srcdir)/der-protos.h $(srcdir)/der-private.h
$(libasn1template_la_OBJECTS): $(nodist_include_HEADERS) $(priv_headers) asn1_err.h $(srcdir)/der-protos.h $(srcdir)/der-private.h
$(libasn1base_la_OBJECTS): asn1_err.h $(srcdir)/der-protos.h $(srcdir)/der-private.h
$(check_gen_OBJECTS): test_asn1.h
$(check_template_OBJECTS): test_asn1_files
$(asn1_print_OBJECTS): $(nodist_include_HEADERS) $(priv_headers)

asn1parse.h: asn1parse.c

$(gen_files_krb5) krb5_asn1.h krb5_asn1-priv.h: krb5_asn1_files
$(gen_files_krb5_template) krb5_template_asn1.h krb5_template_asn1-priv.h: krb5_template_asn1_files
$(gen_files_ocsp) ocsp_asn1.h ocsp_asn1-priv.h: ocsp_asn1_files
$(gen_files_ocsp_template) ocsp_template_asn1.h ocsp_template_asn1-priv.h: ocsp_template_asn1_files
$(gen_files_pkinit) pkinit_asn1.h pkinit_asn1-priv.h: pkinit_asn1_files
$(gen_files_pkinit_template) pkinit_template_asn1.h pkinit_template_asn1-priv.h: pkinit_template_asn1_files
$(gen_files_pkcs8) pkcs8_asn1.h pkcs8_asn1-priv.h: pkcs8_asn1_files
$(gen_files_pkcs8_template) pkcs8_template_asn1.h pkcs8_template_asn1-priv.h: pkcs8_template_asn1_files
$(gen_files_pkcs9) pkcs9_asn1.h pkcs9_asn1-priv.h: pkcs9_asn1_files
$(gen_files_pkcs9_template) pkcs9_template_asn1.h pkcs9_template_asn1-priv.h: pkcs9_template_asn1_files
$(gen_files_pkcs10) pkcs10_asn1.h pkcs10_asn1-priv.h: pkcs10_asn1_files
$(gen_files_pkcs10_template) pkcs10_template_asn1.h pkcs10_template_asn1-priv.h: pkcs10_template_asn1_files
$(gen_files_pkcs12) pkcs12_asn1.h pkcs12_asn1-priv.h: pkcs12_asn1_files
$(gen_files_pkcs12_template) pkcs12_template_asn1.h pkcs12_template_asn1-priv.h: pkcs12_template_asn1_files
$(gen_files_digest) digest_asn1.h digest_asn1-priv.h: digest_asn1_files
$(gen_files_digest_template) digest_template_asn1.h digest_template_asn1-priv.h: digest_template_asn1_files
$(gen_files_kx509) kx509_asn1.h kx509_asn1-priv.h: kx509_asn1_files
$(gen_files_kx509_template) kx509_template_asn1.h kx509_template_asn1-priv.h: kx509_template_asn1_files
$(gen_files_rfc2459) rfc2459_asn1.h rfc2459_asn1-priv.h: rfc2459_asn1_files
$(gen_files_rfc2459_template) rfc2459_template_asn1.h rfc2459_template_asn1-priv.h: rfc2459_template_asn1_files
$(gen_files_rfc4108) rfc4108_asn1.h rfc4108_asn1-priv.h: rfc4108_asn1_files
$(gen_files_rfc4108_template) rfc4108_template_asn1.h rfc4108_template_asn1-priv.h: rfc4108_template_asn1_files
$(gen_files_cms) cms_asn1.h cms_asn1-priv.h: cms_asn1_files
$(gen_files_cms_template) cms_template_asn1.h cms_template_asn1-priv.h: cms_template_asn1_files
$(gen_files_crmf) crmf_asn1.h crmf_asn1-priv.h: crmf_asn1_files
$(gen_files_crmf_template) crmf_template_asn1.h crmf_template_asn1-priv.h: crmf_template_asn1_files
$(gen_files_x690sample) x690sample_asn1.h x690sample_asn1-priv.h: x690sample_asn1_files
$(gen_files_x690sample_template) x690sample_template_asn1.h x690sample_template_asn1-priv.h: x690sample_template_asn1_files
$(gen_files_test) test_asn1.h test_asn1-priv.h: test_asn1_files
$(gen_files_test_template) test_template_asn1.h test_template_asn1-priv.h: test_template_asn1_files

if ASN1_TEMPLATING
TEMPLATE_OPTION=--template
else
TEMPLATE_OPTION=
endif

# If the default is not templating, then we build a variant of libasn1 that is
# templated anyways.
rfc2459_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/rfc2459.asn1
	$(ASN1_COMPILE) --one-code-file --template --option-file=$(srcdir)/rfc2459.opt $(srcdir)/rfc2459.asn1 rfc2459_template_asn1 || (rm -f rfc2459_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_rfc2459_template_asn1.c

rfc4108_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/rfc4108.asn1
	$(ASN1_COMPILE) --one-code-file --template $(srcdir)/rfc4108.asn1 rfc4108_template_asn1 || (rm -f rfc4108_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_rfc4108_template_asn1.c

cms_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/cms.asn1 $(srcdir)/cms.opt
	$(ASN1_COMPILE) --one-code-file --template --option-file=$(srcdir)/cms.opt $(srcdir)/cms.asn1 cms_template_asn1 || (rm -f cms_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_cms_template_asn1.c

crmf_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/crmf.asn1 $(srcdir)/crmf.opt
	$(ASN1_COMPILE) --one-code-file --template --option-file=$(srcdir)/crmf.opt $(srcdir)/crmf.asn1 crmf_template_asn1 || (rm -f crmf_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_crmf_template_asn1.c

krb5_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/krb5.asn1 $(srcdir)/krb5.opt
	$(ASN1_COMPILE) --one-code-file --template			\
			--option-file=$(srcdir)/krb5.opt		\
			$(srcdir)/krb5.asn1 krb5_template_asn1 || (rm -f krb5_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_krb5_template_asn1.c

ocsp_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/ocsp.asn1
	$(ASN1_COMPILE) --one-code-file --template --option-file=$(srcdir)/ocsp.opt $(srcdir)/ocsp.asn1 ocsp_template_asn1 || (rm -f ocsp_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_ocsp_template_asn1.c

pkinit_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkinit.asn1
	$(ASN1_COMPILE) --one-code-file --template $(srcdir)/pkinit.asn1 pkinit_template_asn1 || (rm -f pkinit_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkinit_template_asn1.c

pkcs8_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkcs8.asn1
	$(ASN1_COMPILE) --one-code-file --template $(srcdir)/pkcs8.asn1 pkcs8_template_asn1 || (rm -f pkcs8_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkcs8_template_asn1.c

pkcs9_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkcs9.asn1
	$(ASN1_COMPILE) --one-code-file --template $(srcdir)/pkcs9.asn1 pkcs9_template_asn1 || (rm -f pkcs9_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkcs9_template_asn1.c

pkcs10_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkcs10.asn1
	$(ASN1_COMPILE) --one-code-file --template --option-file=$(srcdir)/pkcs10.opt $(srcdir)/pkcs10.asn1 pkcs10_template_asn1 || (rm -f pkcs10_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkcs10_template_asn1.c

pkcs12_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkcs12.asn1
	$(ASN1_COMPILE) --one-code-file --template $(srcdir)/pkcs12.asn1 pkcs12_template_asn1 || (rm -f pkcs12_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkcs12_template_asn1.c

digest_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/digest.asn1
	$(ASN1_COMPILE) --one-code-file --template $(srcdir)/digest.asn1 digest_template_asn1 || (rm -f digest_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_digest_template_asn1.c

kx509_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/kx509.asn1
	$(ASN1_COMPILE) --one-code-file --template $(srcdir)/kx509.asn1 kx509_template_asn1 || (rm -f kx509_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_kx509_template_asn1.c

rfc2459_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/rfc2459.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) --option-file=$(srcdir)/rfc2459.opt $(srcdir)/rfc2459.asn1 rfc2459_asn1 || (rm -f rfc2459_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_rfc2459_asn1.c

rfc4108_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/rfc4108.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) $(srcdir)/rfc4108.asn1 rfc4108_asn1 || (rm -f rfc4108_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_rfc4108_asn1.c

cms_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/cms.asn1 $(srcdir)/cms.opt
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) --option-file=$(srcdir)/cms.opt $(srcdir)/cms.asn1 cms_asn1 || (rm -f cms_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_cms_asn1.c

crmf_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/crmf.asn1 $(srcdir)/crmf.opt
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) --option-file=$(srcdir)/crmf.opt $(srcdir)/crmf.asn1 crmf_asn1 || (rm -f crmf_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_crmf_asn1.c

krb5_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/krb5.asn1 $(srcdir)/krb5.opt
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION)		\
			--option-file=$(srcdir)/krb5.opt		\
			$(srcdir)/krb5.asn1 krb5_asn1 || (rm -f krb5_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_krb5_asn1.c

ocsp_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/ocsp.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) --option-file=$(srcdir)/ocsp.opt $(srcdir)/ocsp.asn1 ocsp_asn1 || (rm -f ocsp_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_ocsp_asn1.c

pkinit_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkinit.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) $(srcdir)/pkinit.asn1 pkinit_asn1 || (rm -f pkinit_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkinit_asn1.c

pkcs8_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkcs8.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) $(srcdir)/pkcs8.asn1 pkcs8_asn1 || (rm -f pkcs8_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkcs8_asn1.c

pkcs9_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkcs9.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) $(srcdir)/pkcs9.asn1 pkcs9_asn1 || (rm -f pkcs9_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkcs9_asn1.c

pkcs10_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkcs10.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) --option-file=$(srcdir)/pkcs10.opt $(srcdir)/pkcs10.asn1 pkcs10_asn1 || (rm -f pkcs10_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkcs10_asn1.c

pkcs12_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/pkcs12.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) $(srcdir)/pkcs12.asn1 pkcs12_asn1 || (rm -f pkcs12_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_pkcs12_asn1.c

digest_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/digest.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) $(srcdir)/digest.asn1 digest_asn1 || (rm -f digest_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_digest_asn1.c

kx509_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/kx509.asn1
	$(ASN1_COMPILE) --one-code-file $(TEMPLATE_OPTION) $(srcdir)/kx509.asn1 kx509_asn1 || (rm -f kx509_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_kx509_asn1.c

x690sample_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/x690sample.asn1
	$(ASN1_COMPILE) --one-code-file --template $(srcdir)/x690sample.asn1 x690sample_template_asn1 || (rm -f x690sample_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_x690sample_template_asn1.c

x690sample_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/x690sample.asn1
	$(ASN1_COMPILE) --one-code-file $(srcdir)/x690sample.asn1 x690sample_asn1 || (rm -f x690sample_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_x690sample_asn1.c

test_template_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/test.asn1
	$(ASN1_COMPILE) --one-code-file					\
			--template					\
			--option-file=$(srcdir)/test.opt		\
			$(srcdir)/test.asn1 test_template_asn1 || (rm -f test_template_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_test_template_asn1.c

test_asn1_files: asn1_compile$(EXEEXT) $(srcdir)/test.asn1
	$(ASN1_COMPILE) --one-code-file					\
			--option-file=$(srcdir)/test.opt		\
			$(srcdir)/test.asn1 test_asn1 || (rm -f test_asn1_files ; exit 1)
	@$(CLANG_FORMAT) -style=$(CLANG_FORMAT_STYLE) -i asn1_test_asn1.c


EXTRA_DIST =			\
	NTMakefile		\
	README-template.md	\
	asn1_compile-version.rc	\
	libasn1-exports.def	\
	canthandle.asn1		\
	cms.asn1		\
	cms.opt			\
	crmf.asn1		\
	crmf.opt		\
	digest.asn1		\
	krb5.asn1		\
	krb5.opt		\
	kx509.asn1		\
	ocsp.asn1		\
	ocsp.opt		\
	pkcs10.asn1		\
	pkcs10.opt		\
	pkcs12.asn1		\
	pkcs8.asn1		\
	pkcs9.asn1		\
	pkinit.asn1		\
	pku2u.asn1		\
	rfc2459.asn1		\
	rfc2459.opt		\
	rfc4108.asn1		\
	setchgpw2.asn1		\
	tcg.asn1		\
	test.asn1		\
	test.opt		\
	x690sample.asn1		\
	test.gen		\
	asn1_err.et		\
	asn1_err.c		\
	asn1_err.h		\
	asn1_print.1		\
	asn1_compile.1		\
	version-script.map

DER_PROTOS = $(srcdir)/der-protos.h $(srcdir)/der-private.h

ALL_OBJECTS  = $(libasn1_la_OBJECTS)
ALL_OBJECTS += $(libasn1template_la_OBJECTS)
ALL_OBJECTS += $(libasn1base_la_OBJECTS)
ALL_OBJECTS += $(asn1_print_OBJECTS)
ALL_OBJECTS += $(asn1_compile_OBJECTS)
ALL_OBJECTS += $(asn1_gen_OBJECTS)
ALL_OBJECTS += $(check_template_OBJECTS)

$(ALL_OBJECTS): $(DER_PROTOS) asn1_err.h

$(srcdir)/der-protos.h: $(dist_libasn1base_la_SOURCES) $(dist_libasn1_la_SOURCES)
	cd $(srcdir) && perl ../../cf/make-proto.pl -q -P comment -o der-protos.h $(dist_libasn1base_la_SOURCES) $(dist_libasn1_la_SOURCES) || rm -f der-protos.h

$(srcdir)/der-private.h: $(dist_libasn1base_la_SOURCES) $(dist_libasn1_la_SOURCES)
	cd $(srcdir) && perl ../../cf/make-proto.pl -q -P comment -p der-private.h $(dist_libasn1base_la_SOURCES) $(dist_libasn1_la_SOURCES) || rm -f der-private.h
