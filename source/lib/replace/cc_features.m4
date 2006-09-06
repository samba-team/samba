dnl C99 compiler check
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004,2005
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl
dnl adapted for libreplace by Andrew Tridgell

############################################
# Check if the compiler handles c99 struct initialization, and if not try -AC99 and -c99 flags
# Usage: LIBREPLACE_C99_STRUCT_INIT(success-action,failure-action)
# changes CFLAGS to add -AC99 or -c99 if needed

AC_DEFUN([LIBREPLACE_C99_STRUCT_INIT],
[
saved_CFLAGS="$CFLAGS";
c99_init=no
if test x"$c99_init" = x"no"; then
    AC_MSG_CHECKING(for C99 designated initializers)
    CFLAGS="$saved_CFLAGS";
    AC_TRY_COMPILE([#include <stdio.h>],
     [ struct foo {int x;char y;};
       struct foo bar = { .y = 'X', .x = 1 };	 
     ],
     [AC_MSG_RESULT(yes); c99_init=yes],[AC_MSG_RESULT(no)])
fi
if test x"$c99_init" = x"no"; then
    AC_MSG_CHECKING(for C99 designated initializers with -AC99)
    CFLAGS="$saved_CFLAGS -AC99";
    AC_TRY_COMPILE([#include <stdio.h>],
     [ struct foo {int x;char y;};
       struct foo bar = { .y = 'X', .x = 1 };	 
     ],
     [AC_MSG_RESULT(yes); c99_init=yes],[AC_MSG_RESULT(no)])
fi
if test x"$c99_init" = x"no"; then
    AC_MSG_CHECKING(for C99 designated initializers with -c99)
    CFLAGS="$saved_CFLAGS -c99"
    AC_TRY_COMPILE([#include <stdio.h>],
     [ struct foo {int x;char y;};
       struct foo bar = { .y = 'X', .x = 1 };	 
     ],
     [AC_MSG_RESULT(yes); c99_init=yes],[AC_MSG_RESULT(no)])
fi
if test x"$c99_init" = x"yes"; then
    saved_CFLAGS=""
    $1
else
    CFLAGS="$saved_CFLAGS"
    saved_CFLAGS=""
    $2
fi
])
