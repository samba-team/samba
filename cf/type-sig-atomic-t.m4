dnl $Id$
dnl
dnl test for sig_atomic_t

AC_DEFUN(AC_TYPE_SIG_ATOMIC_T,
[AC_MSG_CHECKING(for sig_atomic_t)
AC_CACHE_VAL(ac_cv_type_sig_atomic_t,
AC_TRY_COMPILE(
[#include <signal.h>],
[sig_atomic_t foo = 1;],
ac_cv_type_sig_atomic_t=yes,
ac_cv_type_sig_atomic_t=no))
if test "$ac_cv_type_sig_atomic_t" = no; then
	AC_DEFINE(sig_atomic_t, int)dnl
fi
AC_MSG_RESULT($ac_cv_type_sig_atomic_t)
])
