dnl $Id$
dnl
dnl try to look for an installed roken library with sufficient stuff
dnl
dnl set LIB_roken to the what we should link with
dnl set DIR_roken to if the directory should be built

dnl AC_ROKEN(version,directory-to-try,fallback-string)
AC_DEFUN(AC_ROKEN, [

AC_ARG_WITH(roken,
[  --with-roken=dir	use the roken library in dir],
[if test "$withval" = "no"; then
  AC_MSG_ERROR(roken is required)
fi])

save_CPPFLAGS="${CPPFLAGS}"

case $with_roken in
yes|"")
  dirs="$2" ;;
*)
  dirs="$with_roken" ;;
esac

roken_installed=no

for i in $dirs; do

AC_MSG_CHECKING(for roken in $i)

CPPFLAGS="-I$i/include ${CPPFLAGS}"

AC_TRY_CPP(
[#include <roken.h>
#if ROKEN_VERSION < $1
#error old roken version, should be $1
fail
#endif
],[roken_installed=yes; break])

AC_MSG_RESULT($roken_installed)

done

CPPFLAGS="$save_CPPFLAGS"

if test "$roken_installed" != "yes"; then
  DIR_roken="roken"
  LIB_roken='$3'
else
  LIB_roken="$i/lib/libroken.la"
  CPPFLAGS="-I$i/include ${CPPFLAGS}"
fi

LIB_roken="${LIB_roken} \$(LIB_crypt) \$(LIB_dbopen)"

AC_SUBST(LIB_roken)dnl
AC_SUBST(DIR_roken)dnl
])
