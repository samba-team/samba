dnl $Id$
dnl
dnl test for mode_t

AC_DEFUN(AC_TYPE_MODE_T,
[AC_MSG_CHECKING(for mode_t)
AC_CACHE_VAL(ac_cv_type_mode_t,
AC_TRY_COMPILE(
[#include <sys/types.h>],
[mode_t foo = 1;],
ac_cv_type_mode_t=yes,
ac_cv_type_mode_t=no))
if test "$ac_cv_type_mode_t" = no; then
	AC_DEFINE(mode_t, unsigned short)dnl
fi
AC_MSG_RESULT($ac_cv_type_mode_t)
])
