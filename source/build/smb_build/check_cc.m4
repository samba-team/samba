dnl SMB Build Environment CC Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl
dnl _SMB_BUILD_CHECK_CC(
dnl		1:dummy
dnl		)

dnl #######################################################
dnl ### And now the implementation			###
dnl #######################################################

dnl _SMB_BUILD_CHECK_CC(
dnl		1:dummy
dnl		)
AC_DEFUN([_SMB_BUILD_CHECK_CC],
[
	AC_PROG_CC
	if test x"$CC" = x""; then
		AC_MSG_WARN([No c compiler was not found!])
		AC_MSG_ERROR([Please Install gcc from http://gcc.gnu.org/])
	fi

	AC_PROG_CC_STDC

	# compile with optimization and without debugging by default, but
	# allow people to set their own preference.
	if test "x$CFLAGS" = x; then
		CFLAGS="-O ${CFLAGS}"
	fi

	dnl needed before AC_TRY_COMPILE
	AC_ISC_POSIX

	dnl Check if C compiler understands -c and -o at the same time
	AC_PROG_CC_C_O
	if eval "test \"`echo '$ac_cv_prog_cc_'${ac_cc}_c_o`\" = no"; then
		BROKEN_CC=
	else
		BROKEN_CC=#
	fi
	AC_SUBST(BROKEN_CC)

	AC_CACHE_CHECK([that the C compiler can precompile header files],samba_cv_precompiled_headers, [
		dnl Check whether the compiler can generate precompiled headers
		touch conftest.h
		if ${CC-cc} conftest.h 2> /dev/null && test -f conftest.h.gch; then
			samba_cv_precompiled_headers=yes
		else
			samba_cv_precompiled_headers=no
		fi])
	PCH_AVAILABLE="#"
	if test x"$samba_cv_precompiled_headers" = x"yes"; then
		PCH_AVAILABLE=""
	fi
	AC_SUBST(PCH_AVAILABLE)


	dnl Check if the C compiler understands volatile (it should, being ANSI).
	AC_CACHE_CHECK([that the C compiler understands volatile],samba_cv_volatile, [
		AC_TRY_COMPILE([#include <sys/types.h>],[volatile int i = 0],
			samba_cv_volatile=yes,samba_cv_volatile=no)])
	if test x"$samba_cv_volatile" = x"yes"; then
		AC_DEFINE(HAVE_VOLATILE, 1, [Whether the C compiler understands volatile])
	fi

	AC_C_CONST
	AC_C_INLINE

	AC_PROG_CPP
])
