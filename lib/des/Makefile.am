# $Id$

include $(top_srcdir)/Makefile.am.common

lib_LTLIBRARIES = libdes.la
libdes_la_LDFLAGS = -version-info 3:1:0

include_HEADERS = des.h md4.h md5.h sha.h rc2.h rc4.h aes.h

build_HEADERZ = $(include_HEADERS)

check_PROGRAMS = destest mdtest rctest rc2test #md5crypt_test 

TESTS = $(check_PROGRAMS)

LDADD = $(lib_LTLIBRARIES) $(LIB_roken)

libdes_la_SOURCES =	\
	aes.c		\
	aes.h		\
	des.c		\
	des.h		\
	md4.c		\
	md4.h		\
	md5.c		\
	md5.h		\
	rc2.c		\
	rc2.h		\
	rc4.c		\
	rc4.h		\
	rijndael-alg-fst.c \
	rijndael-alg-fst.h \
	rnd_keys.c	\
	sha.c		\
	sha.h		\
	ui.c
