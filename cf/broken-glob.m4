dnl $Id$
dnl
dnl check for glob(3)
dnl
AC_DEFUN(AC_BROKEN_GLOB,[
AC_CACHE_CHECK(for working glob, ac_cv_func_glob_working,
ac_cv_func_glob_working=yes
AC_TRY_LINK([
#include <stdio.h>
#include <glob.h>],[
glob(NULL, GLOB_BRACE|GLOB_NOCHECK|GLOB_QUOTE|GLOB_TILDE, NULL, NULL);
],:,ac_cv_func_glob_working=no,:))
: << END
@@@funcs="$funcs glob"@@@
END
if test "$ac_cv_func_glob_working" = yes; then
	foo=HAVE_GLOB
	AC_DEFINE_UNQUOTED($foo)
fi
if test "$ac_cv_func_glob_working" = yes; then
AC_NEED_PROTO([#include <stdio.h>
#include <glob.h>],glob)
fi
])
