dnl SMB Build Environment Perl Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl
dnl _SMB_BUILD_CHECK_PERL(
dnl		1:dummy
dnl		)

dnl #######################################################
dnl ### And now the implementation			###
dnl #######################################################

dnl _SMB_BUILD_CHECK_PERL(
dnl		1:dummy
dnl		)
AC_DEFUN([_SMB_BUILD_CHECK_PERL],
[
	AC_PATH_PROG(PERL, perl)
	if test x"$PERL" = x""; then
		AC_MSG_WARN([No version of perl was not found!])
		AC_MSG_ERROR([Please Install perl from http://www.perl.com/])
	fi
	if test x"$debug" = x"yes";then
		PERL="$PERL -W"
	fi
])
