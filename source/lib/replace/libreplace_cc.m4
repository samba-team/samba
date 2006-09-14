
AC_DEFUN_ONCE(AC__LIBREPLACE_ONLY_CC_CHECKS_START,
[
echo "LIBREPLACE_CC_CHECKS: START"
])

AC_DEFUN_ONCE(AC__LIBREPLACE_ONLY_CC_CHECKS_END,
[
echo "LIBREPLACE_CC_CHECKS: END"
])

dnl
dnl
dnl AC_LIBREPLACE_CC_CHECKS
dnl
dnl Note: we need to use m4_define instead of AC_DEFUN because
dnl       of the ordering of tests
dnl       
dnl 
m4_define(AC_LIBREPLACE_CC_CHECKS,
[
AC__LIBREPLACE_ONLY_CC_CHECKS_START

dnl stop the C89 attempt by autoconf - if autoconf detects -Ae it will enable it
dnl which conflicts with C99 on HPUX
ac_cv_prog_cc_Ae=no

savedCFLAGS=$CFLAGS
AC_PROG_CC
CFLAGS=$savedCFLAGS
AC_ISC_POSIX
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_CC_C99
AC_C_INLINE
AC_C_BIGENDIAN
AC_PROG_INSTALL


AC_EXTENSION_FLAG(_XOPEN_SOURCE_EXTENDED)
AC_EXTENSION_FLAG(_OSF_SOURCE)

LIBREPLACE_C99_STRUCT_INIT([],[AC_MSG_WARN([c99 structure initializer are not supported])])

AC_SYS_LARGEFILE

dnl Add #include for broken IRIX header files
case "$host_os" in
	*irix6*) AC_ADD_INCLUDE(<standards.h>)
		;;
	*hpux*)
		# mmap on HPUX is completely broken...
		AC_DEFINE(MMAP_BLACKLIST, 1, [Whether MMAP is broken])
		;;
	*aix*)
		if test "${GCC}" != "yes"; then
			## for funky AIX compiler using strncpy()
			CFLAGS="$CFLAGS -D_LINUX_SOURCE_COMPAT -qmaxmem=32000"
		fi
		;;
	#
	# VOS may need to have POSIX support and System V compatibility enabled.
	#
	*vos*)
		case "$CFLAGS" in
			*-D_POSIX_C_SOURCE*);;
			*)
				CFLAGS="$CFLAGS -D_POSIX_C_SOURCE=200112L"
				AC_DEFINE(_POSIX_C_SOURCE, 200112L, [Whether to enable POSIX support])
				;;
		esac
		case "$CFLAGS" in
			*-D_SYSV*|*-D_SVID_SOURCE*);;
			*)
				CFLAGS="$CFLAGS -D_SYSV"
				AC_DEFINE(_SYSV, 1, [Whether to enable System V compatibility])
				;;
		esac
		;;
esac



AC_CHECK_HEADERS([standards.h])

# Solaris needs HAVE_LONG_LONG defined
AC_CHECK_TYPES(long long)

AC_CHECK_TYPE(uint_t, unsigned int)
AC_CHECK_TYPE(int8_t, char)
AC_CHECK_TYPE(uint8_t, unsigned char)
AC_CHECK_TYPE(int16_t, short)
AC_CHECK_TYPE(uint16_t, unsigned short)
AC_CHECK_TYPE(int32_t, long)
AC_CHECK_TYPE(uint32_t, unsigned long)
AC_CHECK_TYPE(int64_t, long long)
AC_CHECK_TYPE(uint64_t, unsigned long long)

AC_CHECK_TYPE(size_t, unsigned int)
AC_CHECK_TYPE(ssize_t, int)

AC_CHECK_SIZEOF(int)
AC_CHECK_SIZEOF(char)
AC_CHECK_SIZEOF(short)
AC_CHECK_SIZEOF(long)
AC_CHECK_SIZEOF(long long)

AC_CHECK_SIZEOF(off_t)
AC_CHECK_SIZEOF(size_t)
AC_CHECK_SIZEOF(ssize_t)

AC_CHECK_TYPE(intptr_t, unsigned long long)
AC_CHECK_TYPE(ptrdiff_t, unsigned long long)

if test x"$ac_cv_type_long_long" != x"yes";then
	AC_MSG_ERROR([LIBREPLACE needs type 'long long'])
fi
if test $ac_cv_sizeof_long_long -lt 8;then
	AC_MSG_ERROR([LIBREPLACE needs sizeof(long long) >= 8])
fi

AC__LIBREPLACE_ONLY_CC_CHECKS_END
]) dnl end AC_LIBREPLACE_CC_CHECKS
