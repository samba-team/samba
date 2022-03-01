dnl $Id$
dnl
dnl
dnl OLD: We prefer byacc or yacc because they do not use `alloca'
dnl
dnl CURRENT: We don't mind `alloca', but we do mind `bison -y' because
dnl          newer versions of `bison', with `-y' complain about %expect and
dnl          anything that yacc didn't document.  Because `bison' typically
dnl          also installs a `yacc' link that acts like `bison y', we put
dnl          `yacc' last in this list.
dnl

AC_DEFUN([AC_KRB_PROG_YACC],
[AC_CHECK_PROGS(YACC, 'bison -d' 'byacc -d' yacc)
if test "$YACC" = ""; then
  AC_MSG_WARN([byacc and bison not found - some stuff will not build])
fi
])
