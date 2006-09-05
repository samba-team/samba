AC_DEFUN([SMB_EXT_LIB], [echo -n ""])
AC_DEFUN([SMB_ENABLE], [echo -n ""])

AC_PREREQ(2.50)
AC_INIT(dlfcn.c)
AC_CONFIG_SRCDIR([dlfcn.c])
AC_CONFIG_HEADER(replace_config.h)
AC_PROG_INSTALL
AC_PROG_CC

if test "$ac_cv_prog_gcc" = yes; then
   CFLAGS="$CFLAGS -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings"
fi

sinclude(config.m4)
sinclude(win32/config.m4)
sinclude(repdir/config.m4)
AC_OUTPUT(Makefile)
