dnl $Id$
dnl
dnl check for Xau{Read,Write}Auth
dnl
AC_DEFUN(AC_CHECK_XAU,[
save_CFLAGS="$CFLAGS"
CFLAGS="$X_CFLAGS $CFLAGS"
save_LIBS="$LIBS"
dnl LIBS="$X_LIBS $X_PRE_LIBS $X_EXTRA_LIBS $LIBS"
LIBS="$X_PRE_LIBS $X_EXTRA_LIBS $LIBS"
save_LDFLAGS="$LDFLAGS"
LDFLAGS="$LDFLAGS $X_LIBS"

AC_FIND_FUNC_NO_LIBS(XauReadAuth, Xau X11)
ac_xxx="$LIBS"
LIBS="$LIB_XauReadAuth $LIBS"
AC_CHECK_FUNCS(XauWriteAuth)
LIBS="$ac_xxx"
AM_CONDITIONAL(NEED_WRITEAUTH, test "$ac_cv_func_XauWriteAuth" != "yes")

CFLAGS=$save_CFLAGS
LIBS=$save_LIBS
LDFLAGS=$save_LDFLAGS
])
