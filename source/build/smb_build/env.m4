dnl SMB Build Environment Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl
dnl _SMB_BUILD_ENV(
dnl		1:dummy
dnl		)

dnl #######################################################
dnl ### And now the implementation			###
dnl #######################################################

dnl _SMB_BUILD_ENV(
dnl		1:dummy
dnl		)
AC_DEFUN([_SMB_BUILD_ENV],
[
	SMB_VERSION_STRING=`cat include/version.h | grep 'SAMBA_VERSION_OFFICIAL_STRING' | cut -d '"' -f2`
	echo "SAMBA VERSION: ${SMB_VERSION_STRING}"

	_SMB_BUILD_CHECK_PATH([])

	_SMB_BUILD_CHECK_PERL([])

	_SMB_BUILD_CHECK_CC([])

	_SMB_BUILD_CHECK_LD([])

	_SMB_BUILD_CHECK_SHLD([])

	AC_CANONICAL_BUILD
	AC_CANONICAL_HOST
	AC_CANONICAL_TARGET
	
	AC_VALIDATE_CACHE_SYSTEM_TYPE

	_SMB_BUILD_CHECK_TYPES([])

	AC_PROG_INSTALL
])
