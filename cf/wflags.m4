dnl $Id$
dnl
dnl set WFLAGS

AC_DEFUN(AC_WFLAGS,[
WFLAGS_NOUNUSED=""
WFLAGS_NORETURNTYPE=""
if test -z "$WFLAGS" -a "$GCC" = "yes"; then
  # -Wno-return-type for broken X11 headers
  # leave these out for now:
  #   -Wcast-align doesn't work well on alpha osf/1
  #   -Wmissing-prototypes -Wpointer-arith -Wbad-function-cast
  #   -Wmissing-declarations -Wnested-externs
  WFLAGS="ifelse($#, 0,-Wall -Wno-return-type, $1)"
  WFLAGS_NOUNUSED="-Wno-unused"
  WFLAGS_NORETURNTYPE="-Wno-return-type"
fi
AC_SUBST(WFLAGS)dnl
AC_SUBST(WFLAGS_NOUNUSED)dnl
AC_SUBST(WFLAGS_NORETURNTYPE)dnl
])
