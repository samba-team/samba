# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libdes.la
libdes_la_LDFLAGS = -version-info 3:1:0
libdes_la_LIBADD = \
	$(top_builddir)/lib/asn1/libasn1.la \
	$(LIB_roken)

include_HEADERS =	\
	aes.h		\
	bn.h		\
	des.h		\
	dh.h		\
	dsa.h		\
	evp.h		\
	engine.h	\
	hmac.h		\
	md2.h		\
	md4.h		\
	md5.h		\
	rand.h		\
	rc2.h		\
	rc4.h		\
	rsa.h		\
	sha.h		\
	ui.h

build_HEADERZ = $(include_HEADERS)

noinst_PROGRAMS = test_engine_dso

check_PROGRAMS = \
	destest \
	mdtest \
	rc2test  \
	rctest \
	test_bn \
	test_hmac

# md5crypt_test 

TESTS = $(check_PROGRAMS)

LDADD = $(lib_LTLIBRARIES) $(LIB_roken)

libdes_la_SOURCES =	\
	aes.c		\
	aes.h		\
	bn.c		\
	bn.h		\
	des.c		\
	des.h		\
	dh.c		\
	dh.h		\
	dsa.c		\
	dsa.h		\
	evp.c		\
	evp.h		\
	engine.h	\
	engine.c	\
	hmac.c		\
	hmac.h		\
	md2.c		\
	md2.h		\
	md4.c		\
	md4.h		\
	md5.c		\
	md5.h		\
	rand.h		\
	rand.c		\
	rc2.c		\
	rc2.h		\
	rc4.c		\
	rc4.h		\
	rsa.c		\
	rsa.h		\
	rijndael-alg-fst.c \
	rijndael-alg-fst.h \
	rnd_keys.c	\
	sha.c		\
	sha.h		\
	ui.c		\
	ui.h
