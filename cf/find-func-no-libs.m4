dnl $Id$
dnl
dnl
dnl Look for function in any of the specified libraries
dnl

dnl AC_FIND_FUNC_NO_LIBS(func, libraries, includes, arguments)
AC_DEFUN(AC_FIND_FUNC_NO_LIBS, [
AC_FIND_FUNC_NO_LIBS2([$1], ["" $2], [$3], [$4])])
