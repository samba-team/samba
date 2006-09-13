AC_PREREQ(2.50)
AC_INIT(replace.c)
AC_CONFIG_SRCDIR([replace.c])
AC_CONFIG_HEADER(config.h)

m4_include(libreplace.m4)

if test "$ac_cv_prog_gcc" = yes; then
   CFLAGS="$CFLAGS -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings"
fi

AC_OUTPUT(Makefile)
