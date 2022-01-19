dnl
dnl $Id$
dnl
dnl test for POSIX (broken) getlogin
dnl


AC_DEFUN([AC_FUNC_GETLOGIN], [
AC_CHECK_FUNCS(getlogin getlogin_r setlogin)
if test "$ac_cv_func_getlogin" = yes; then
AC_CACHE_CHECK(if getlogin is posix, ac_cv_func_getlogin_posix, [
if test "$ac_cv_func_getlogin" = yes -a "$ac_cv_func_setlogin" = yes; then
	ac_cv_func_getlogin_posix=no
else
	ac_cv_func_getlogin_posix=yes
fi
])
AC_CACHE_CHECK(if getlogin_r is posix, ac_cv_func_getlogin_r_posix, [
if test "$ac_cv_func_getlogin_r" = yes -a "$ac_cv_func_setlogin" = yes; then
	ac_cv_func_getlogin_r_posix=no
else
	ac_cv_func_getlogin_r_posix=yes
fi
])
if test "$ac_cv_func_getlogin_posix" = yes; then
	AC_DEFINE(POSIX_GETLOGIN, 1, [Define if getlogin has POSIX flavour (and not BSD).])
fi
if test "$ac_cv_func_getlogin_r_posix" = yes; then
	AC_DEFINE(POSIX_GETLOGIN_R, 1, [Define if getlogin_r has POSIX flavour (and not BSD).])
fi
fi
])
