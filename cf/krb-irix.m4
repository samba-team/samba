dnl
dnl $Id$
dnl

dnl requires AC_CANONICAL_HOST
AC_DEFUN(KRB_IRIX,[
irix=no
case "$host_os" in
irix*) irix=yes ;;
esac
AM_CONDITIONAL(IRIX, test "$irix" != no)dnl
])
