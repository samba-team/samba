dnl SMB Build Environment Types Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

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
