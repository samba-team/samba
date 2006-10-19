# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libhcrypto.la
libhcrypto_la_LDFLAGS = -version-info 3:1:0
libhcrypto_la_LIBADD = \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_dlopen) \
	$(LIB_roken)

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

TESTS = \
	test_engine_dso \
	destest \
	mdtest \
	rc2test  \
	rctest \
	test_bn \
	test_cipher \
	test_pkcs5 \
	test_pkcs12 \
	test_hmac

check_PROGRAMS = $(TESTS)


LDADD = $(lib_LTLIBRARIES) $(LIB_roken)

libhcrypto_la_SOURCES =	\
	$(imathsource)	\
	aes.c		\
	aes.h		\
	bn.c		\
	bn.h		\
	des-tables.h	\
	des.c		\
	des.h		\
	dh.c		\
	dh.h		\
	dh-imath.c	\
	dsa.c		\
	dsa.h		\
	evp.c		\
	evp.h		\
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
	rand.c		\
	rand.h		\
	rand-unix.c	\
	rc2.c		\
	rc2.h		\
	rc4.c		\
	rc4.h		\
	rijndael-alg-fst.c \
	rijndael-alg-fst.h \
	rnd_keys.c	\
	rsa.c		\
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
	imath/imrat.c		\
	imath/imrat.h		\
	imath/iprime.c		\
	imath/iprime.h		\
	imath/rsamath.c		\
	imath/rsamath.h

$(libhcrypto_la_OBJECTS): hcrypto-link

hcrypto-link:
	$(LN_S) $(srcdir)/../des hcrypto
	touch hcrypto-link

CLEANFILES = hcrypto hcrypto-link
