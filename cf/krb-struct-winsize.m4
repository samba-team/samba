dnl $Id$
dnl
dnl
dnl Search for struct winsize
dnl

AC_DEFUN(AC_KRB_STRUCT_WINSIZE, [
AC_MSG_CHECKING(for struct winsize)
AC_CACHE_VAL(ac_cv_struct_winsize, [
ac_cv_struct_winsize=no
for i in sys/termios.h sys/ioctl.h; do
AC_EGREP_HEADER(
changequote(, )dnl
struct[ 	]*winsize,dnl
changequote([,])dnl
$i, ac_cv_struct_winsize=yes; break)dnl
done
])
if test "$ac_cv_struct_winsize" = "yes"; then
  AC_DEFINE(HAVE_STRUCT_WINSIZE, 1)dnl
fi
AC_MSG_RESULT($ac_cv_struct_winsize)
AC_EGREP_HEADER(ws_xpixel, termios.h, AC_DEFINE(HAVE_WS_XPIXEL))
AC_EGREP_HEADER(ws_ypixel, termios.h, AC_DEFINE(HAVE_WS_YPIXEL))
])
