# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libhcrypto.la
check_LTLIBRARIES = libhctest.la

libhcrypto_la_LDFLAGS = -version-info 5:0:1
libhcrypto_la_LIBADD = \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_dlopen) \
	$(LIBADD_roken)

hcryptoincludedir = $(includedir)/hcrypto
buildhcryptoinclude = $(buildinclude)/hcrypto

hcryptoinclude_HEADERS =	\
	aes.h			\
	bn.h			\
	des.h			\
	dh.h			\
	dsa.h			\
	engine.h		\
	evp.h			\
	hmac.h			\
	md2.h			\
	md4.h			\
	md5.h			\
	pkcs12.h		\
	rand.h			\
	rc2.h			\
	rc4.h			\
	rsa.h			\
	sha.h			\
	ui.h

install-build-headers:: $(hcryptoinclude_HEADERS)
	@foo='$(hcryptoinclude_HEADERS)'; \
	for f in $$foo; do \
		f=`basename $$f`; \
		if test -f "$(srcdir)/$$f"; then file="$(srcdir)/$$f"; \
		else file="$$f"; fi; \
		if cmp -s  $$file $(buildhcryptoinclude)/$$f 2> /dev/null ; then \
		: ; else \
			echo "cp $$file $(buildhcryptoinclude)/$$f";\
			cp $$file $(buildhcryptoinclude)/$$f; \
		fi ; \
	done

PROGRAM_TESTS = \
	destest \
	mdtest \
	rc2test  \
	rctest \
	test_bn \
	test_cipher \
	test_engine_dso \
	test_hmac \
	test_imath \
	test_pkcs12 \
	test_pkcs5

libhctest_la_SOURCES = \
	imath/imath.c	\
	des-tables.h	\
	des.c		\
	des.h		\
	ui.c		\
	ui.h

test_imath_LDADD = libhctest.la $(LIB_roken)
destest_LDADD = libhctest.la $(LIB_roken)

SCRIPT_TESTS = \
	test_crypto

noinst_PROGRAMS = test_rand

check_PROGRAMS = $(PROGRAM_TESTS) test_rsa test_dh example_evp_cipher
check_SCRIPTS = $(SCRIPT_TESTS)

TESTS = $(PROGRAM_TESTS) $(SCRIPT_TESTS)

LDADD = $(lib_LTLIBRARIES) $(LIB_roken)

libhcrypto_la_SOURCES =	\
	$(imathsource)	\
	aes.c		\
	aes.h		\
	bn.c		\
	bn.h		\
	camellia.h	\
	camellia.c	\
	camellia-ntt.c	\
	camellia-ntt.h	\
	des-tables.h	\
	des.c		\
	des.h		\
	dh.c		\
	dh.h		\
	dh-imath.c	\
	dsa.c		\
	dsa.h		\
	doxygen.c	\
	evp.c		\
	evp.h		\
	evp-hcrypto.c	\
	evp-aes-cts.c	\
	engine.c	\
	engine.h	\
	hash.h		\
	hmac.c		\
	hmac.h		\
	md2.c		\
	md2.h		\
	md4.c		\
	md4.h		\
	md5.c		\
	md5.h		\
	pkcs5.c		\
	pkcs12.c	\
	rand-egd.c	\
	rand-fortuna.c	\
	rand-timer.c	\
	rand-unix.c	\
	rand.c		\
	rand.h		\
	randi.h		\
	rc2.c		\
	rc2.h		\
	rc4.c		\
	rc4.h		\
	rijndael-alg-fst.c \
	rijndael-alg-fst.h \
	rnd_keys.c	\
	rsa.c		\
	rsa-gmp.c	\
	rsa-imath.c	\
	rsa.h		\
	sha.c		\
	sha.h		\
	sha256.c	\
	ui.c		\
	ui.h

imathsource =			\
	imath/imath.c		\
	imath/imath.h		\
	imath/iprime.c		\
	imath/iprime.h

$(libhcrypto_la_OBJECTS): hcrypto-link

libhcrypto_la_CPPFLAGS = -DIMATH_LARGE_PRIME_TABLE -DBUILD_HCRYPTO_LIB $(AM_CPPFLAGS)

if versionscript
libhcrypto_la_LDFLAGS += $(LDFLAGS_VERSION_SCRIPT)$(srcdir)/version-script.map
endif
$(libhcrypto_la_OBJECTS): $(srcdir)/version-script.map


hcrypto-link:
	$(LN_S) $(srcdir)/../hcrypto hcrypto
	touch hcrypto-link

do_subst = sed -e 's,[@]srcdir[@],$(srcdir),g'

test_crypto: test_crypto.in Makefile
	$(do_subst) < $(srcdir)/test_crypto.in > test_crypto.tmp
	chmod +x test_crypto.tmp
	mv test_crypto.tmp test_crypto

CLEANFILES = \
	crypto-test \
	crypto-test2 \
	error \
	hcrypto \
	hcrypto-link \
	test.file \
	test_crypto \
	test-out* \
	test_crypto.tmp \
	test_crypto.tmp

EXTRA_DIST = \
	DESperate.txt \
	dllmain.c \
	ec.h \
	ecdh.h \
	ecdsa.h \
	gen-des.pl \
	imath/LICENSE \
	imath/import.sh \
	md5crypt_test.c \
	passwd_dialog.aps \
	passwd_dialog.clw \
	passwd_dialog.rc \
	passwd_dialog.res \
	passwd_dlg.c \
	passwd_dlg.h \
	resource.h \
	rsakey.der \
	test_crypto.in \
	version-script.map
