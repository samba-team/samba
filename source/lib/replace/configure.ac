AC_DEFUN([SMB_EXT_LIB], [echo -n ""])
AC_DEFUN([SMB_ENABLE], [echo -n ""])

AC_PREREQ(2.50)
AC_INIT(dlfcn.c)
AC_CONFIG_SRCDIR([dlfcn.c])
AC_CONFIG_HEADER(config.h)
AC_PROG_INSTALL
AC_PROG_CC

if test "$ac_cv_prog_gcc" = yes; then
   CFLAGS="$CFLAGS -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings"
fi

m4_include(libreplace.m4)
m4_include(win32/config.m4)
m4_include(repdir/config.m4)
AC_OUTPUT(Makefile)
