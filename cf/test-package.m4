dnl $Id$
dnl
dnl AC_TEST_PACKAGE(package,header,lib,linkline,default location)
AC_DEFUN(AC_TEST_PACKAGE,
[
AC_MSG_CHECKING(for $1)
AC_ARG_WITH($1,
[  --with-$1=dir                use $1 in dir],
[if test "$with_$1" = "no"; then
  with_$1=
fi]
)
AC_ARG_WITH($1-lib,
[  --with-$1-lib=dir            use $1-lib in dir],
[if test "$withval" = "yes" -o "$withval" = "no"; then
  AC_MSG_ERROR([No argument for --with-$1-lib])
elif test "X$with_$1" = "X"; then
  with_$1=yes
fi]
)
AC_ARG_WITH($1-include,
[  --with-$1-include=dir        use $1-include in dir],
[if test "$withval" = "yes" -o "$withval" = "no"; then
  AC_MSG_ERROR([No argument for --with-$1-include])
elif test "X$with_$1" = "X"; then
  with_$1=yes
fi]
)

define([foo], translit($1, [a-z], [A-Z]))
if test -n "$with_$1" -o -n "$5"; then
dnl  AC_DEFINE([foo])
  if test -n "$with_$1" -a "$with_$1" != "yes"; then
    $1_dir="$with_$1"
  elif test -n "$5"; then
    $1_dir="$5"
  fi
dnl Try to find include
  if test -n "$with_$1_include"; then
    trydir=$with_$1_include
  elif test -n "$with_$1" -a "$with_$1" != "yes"; then
    trydir="$with_$1 $with_$1/include"
  elif test -n "$5"; then
    trydir="$5/include"
  else
    trydir=
  fi
  found=
  for i in $trydir ""; do
    if test -n "$i"; then
      if test -f $i/$2; then
        found=yes; res=$i; break
      fi
    else
      AC_TRY_CPP([#include <$2>], [found=yes; res=$i; break])
    fi
  done
  if test -n "$found"; then
    $1_include=$res
  elif test -n "$with_$1"; then
    AC_MSG_ERROR(Cannot find $2)
  fi
dnl Try to find lib
  if test -n "$with_$1_lib"; then
    trydir=$with_$1_lib
  elif test -n "$with_$1" -a "$with_$1" != "yes"; then
    trydir="$with_$1 $with_$1/lib"
  elif test -n "$5"; then
    trydir="$5/lib"
  else
    trydir=
  fi
  found=
  for i in $trydir ""; do
    if test -n "$i"; then
      if test -f $i/$3; then
        found=yes; res=$i; break
      fi
    else
      old_LIBS=$LIBS
      LIBS="$4 $LIBS"
      AC_TRY_LINK([], [], [found=yes; res=$i; LIBS=$old_LIBS; break])
      LIBS=$old_LIBS
    fi
  done
  if test -n "$found"; then
    $1_lib=$res
  elif test -n "$with_$1"; then
    AC_MSG_ERROR(Cannot find $3)
  fi
  if test -n "$$1_include" -o -n "$$1_lib"; then
    AC_MSG_RESULT([headers $$1_include, libraries $$1_lib])
    AC_DEFINE_UNQUOTED(foo, 1, [Define if you have the $1 package])
    if test "$with_$1" = "" -a "$5"; then
      with_$1="$5"
    fi
  else
    AC_MSG_RESULT(no)
  fi
  if test -n "$$1_include"; then
    INCLUDE_$1="-I$$1_include"
  fi
  AC_SUBST(INCLUDE_$1)
  foo[INCLUDE]="$INCLUDE_$1"
  AC_SUBST(foo[INCLUDE])
  if test -n "$$1_lib"; then
    LIB_$1="-L$$1_lib"
  fi
  LIB_$1="$LIB_$1 $4"
  AC_SUBST(LIB_$1)
  foo[LIB]="$LIB_$1"
  AC_SUBST(foo[LIB])
else
  AC_MSG_RESULT(no)
fi
undefine([foo])
])

