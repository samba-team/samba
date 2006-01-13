dnl $Id$
dnl
dnl test for crypto libraries:
dnl - libcrypto (from openssl)
dnl - libdes (from krb4)
dnl - own-built libdes

m4_define([test_headers], [
		#undef KRB5 /* makes md4.h et al unhappy */
		#ifdef HAVE_OPENSSL
		#ifdef HAVE_SYS_TYPES_H
		#include <sys/types.h>
		#endif
		#include <openssl/md4.h>
		#include <openssl/md5.h>
		#include <openssl/sha.h>
		#include <openssl/des.h>
		#include <openssl/rc4.h>
		#include <openssl/aes.h>
		#include <openssl/ui.h>
		#include <openssl/rand.h>
		#include <openssl/evp.h>
		#include <openssl/hmac.h>
		#include <openssl/pkcs12.h>
		#else
		#include <md4.h>
		#include <md5.h>
		#include <sha.h>
		#include <des.h>
		#include <rc4.h>
		#include <aes.h>
		#include <evp.h>
		#include <hmac.h>
		#include <pkcs12.h>
		#endif
		])
m4_define([test_body], [
		void *schedule = 0;
		MD4_CTX md4;
		MD5_CTX md5;
		SHA_CTX sha1;

		MD4_Init(&md4);
		MD5_Init(&md5);
		SHA1_Init(&sha1);
		#ifdef HAVE_OPENSSL
		RAND_status();
		UI_UTIL_read_pw_string(0,0,0,0);
		#endif

		AES_encrypt(0,0,0);
		DES_cbc_encrypt(0, 0, 0, schedule, 0, 0);
		RC4(0, 0, 0, 0);])


AC_DEFUN([KRB_CRYPTO],[
crypto_lib=unknown
AC_WITH_ALL([openssl])

DIR_des=

AC_MSG_CHECKING([for crypto library])

openssl=no

if test "$crypto_lib" = "unknown" -a "$with_krb4" != "no"; then
	save_CPPFLAGS="$CPPFLAGS"
	save_LIBS="$LIBS"

	cdirs= clibs=
	for i in $LIB_krb4; do
		case "$i" in
		-L*) cdirs="$cdirs $i";;
		-l*) clibs="$clibs $i";;
		esac
	done

	ires=
	for i in $INCLUDE_krb4; do
		CFLAGS="-DHAVE_OPENSSL $i $save_CFLAGS"
		for j in $cdirs; do
			for k in $clibs; do
				LIBS="$j $k $save_LIBS"
				AC_LINK_IFELSE([AC_LANG_PROGRAM([test_headers],
						[test_body])],
					[openssl=yes ires="$i" lres="$j $k"; break 3])
			done
		done
		CFLAGS="$i $save_CFLAGS"
		for j in $cdirs; do
			for k in $clibs; do
				LIBS="$j $k $save_LIBS"
				AC_LINK_IFELSE([AC_LANG_PROGRAM([test_headers],[test_body])],
					[openssl=no ires="$i" lres="$j $k"; break 3])
			done
		done
	done
		
	CFLAGS="$save_CFLAGS"
	LIBS="$save_LIBS"
	if test "$ires" -a "$lres"; then
		INCLUDE_des="$ires"
		LIB_des="$lres"
		crypto_lib=krb4
		AC_MSG_RESULT([same as krb4])
		LIB_des_a='$(LIB_des)'
		LIB_des_so='$(LIB_des)'
		LIB_des_appl='$(LIB_des)'
	fi
fi

if test "$crypto_lib" = "unknown" -a "$with_openssl" != "no"; then
	save_CFLAGS="$CFLAGS"
	save_LIBS="$LIBS"
	INCLUDE_des=
	LIB_des=
	if test "$with_openssl_include" != ""; then
		INCLUDE_des="-I${with_openssl_include}"
	fi
	if test "$with_openssl_lib" != ""; then
		LIB_des="-L${with_openssl_lib}"
	fi
	CFLAGS="-DHAVE_OPENSSL ${INCLUDE_des} ${CFLAGS}"
	saved_LIB_des="$LIB_des"
	for lres in "" "-lnsl -lsocket"; do
		LIB_des="${saved_LIB_des} -lcrypto $lres"
		LIB_des_a="$LIB_des"
		LIB_des_so="$LIB_des"
		LIB_des_appl="$LIB_des"
		LIBS="${LIBS} ${LIB_des}"
		AC_LINK_IFELSE([AC_LANG_PROGRAM([test_headers],[test_body])], [
			crypto_lib=libcrypto openssl=yes
			AC_MSG_RESULT([libcrypto])
		])
		if test "$crypto_lib" = libcrypto ; then
			break;
		fi
	done
	CFLAGS="$save_CFLAGS"
	LIBS="$save_LIBS"
fi

if test "$crypto_lib" = "unknown"; then

  DIR_des='des'
  LIB_des='$(top_builddir)/lib/des/libdes.la'
  LIB_des_a='$(top_builddir)/lib/des/.libs/libdes.a'
  LIB_des_so='$(top_builddir)/lib/des/.libs/libdes.so'
  LIB_des_appl="-ldes"

  AC_MSG_RESULT([included libdes])

fi

if test "$with_krb4" != no -a "$crypto_lib" != krb4; then
	AC_MSG_ERROR([the crypto library used by krb4 lacks features
required by Kerberos 5; to continue, you need to install a newer 
Kerberos 4 or configure --without-krb4])
fi

if test "$openssl" = "yes"; then
  AC_DEFINE([HAVE_OPENSSL], 1, [define to use openssl's libcrypto])
fi
AM_CONDITIONAL(HAVE_OPENSSL, test "$openssl" = yes)dnl

AC_SUBST(DIR_des)
AC_SUBST(INCLUDE_des)
AC_SUBST(LIB_des)
AC_SUBST(LIB_des_a)
AC_SUBST(LIB_des_so)
AC_SUBST(LIB_des_appl)
])
