dnl SMB Build Environment Types Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl
dnl _SMB_BUILD_CHECK_TYPES(
dnl		1:dummy
dnl		)

dnl #######################################################
dnl ### And now the implementation			###
dnl #######################################################

dnl _SMB_BUILD_CHECK_TYPES(
dnl		1:dummy
dnl		)
AC_DEFUN([_SMB_BUILD_CHECK_TYPES],
[
	dnl Add #include for broken IRIX header files
	case "$host_os" in
		*irix6*) AC_ADD_INCLUDE(<standards.h>)
			;;
	esac

	AC_C_BIGENDIAN

	AC_HEADER_STDC

	dnl This should be removed and fixed cleanly --metze
	_AC_INCLUDES_DEFAULT_REQUIREMENTS

	AC_CHECK_HEADERS(stdbool.h)

	AC_CHECK_SIZEOF(short,cross)
	AC_CHECK_SIZEOF(int,cross)
	AC_CHECK_SIZEOF(long,cross)
	AC_CHECK_SIZEOF(long long,cross)
	if test x"$ac_cv_type_long_long" != x"yes";then
		AC_MSG_ERROR([Sorry we need type 'long long'])
	fi
	if test $ac_cv_sizeof_long_long -lt 8;then
		AC_MSG_ERROR([Sorry we need sizeof(long long) >= 8])
	fi
	AC_CHECK_TYPE(_Bool)
	AC_CHECK_TYPE(uint_t, unsigned int)
	AC_CHECK_TYPE(int8_t, signed char)
	AC_CHECK_TYPE(uint8_t, unsigned char)
	AC_CHECK_TYPE(int16_t, short)
	AC_CHECK_TYPE(uint16_t, unsigned short)
	AC_CHECK_TYPE(int32_t, long)
	AC_CHECK_TYPE(uint32_t, unsigned long)
	AC_CHECK_TYPE(int64_t, long long)
	AC_CHECK_TYPE(uint64_t, unsigned long long)

])
