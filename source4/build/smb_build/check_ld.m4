dnl SMB Build Environment LD Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl
dnl _SMB_BUILD_CHECK_LD(
dnl		1:dummy
dnl		)

dnl #######################################################
dnl ### And now the implementation			###
dnl #######################################################

dnl _SMB_BUILD_CHECK_LD(
dnl		1:dummy
dnl		)
AC_DEFUN([_SMB_BUILD_CHECK_LD],
[
	dnl Check if we use GNU ld
	AC_PATH_PROG(LD, ld)
	AC_PROG_LD_GNU
])
