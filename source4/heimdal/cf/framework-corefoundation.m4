AC_DEFUN([rk_FRAMEWORK_COREFOUNDATION], [

AC_MSG_CHECKING([for framework CoreFoundation])
AC_CACHE_VAL(rk_cv_framework_corefoundation,
[
if test "$rk_cv_framework_corefoundation" != yes; then
	ac_save_LIBS="$LIBS"
	LIBS="$ac_save_LIBS -framework CoreFoundation"
	AC_LINK_IFELSE([AC_LANG_PROGRAM([[#include <CoreFoundation/CoreFoundation.h>
]],
[[CFURLRef url;
char path[] = "/";
url = CFURLCreateFromFileSystemRepresentation(kCFAllocatorDefault, (UInt8 *)
path, strlen(path), FALSE);
CFRelease(url);
]])],[rk_cv_framework_corefoundation=yes])
	LIBS="$ac_save_LIBS"
fi
])

if test "$rk_cv_framework_corefoundation" = yes; then
   AC_DEFINE(HAVE_FRAMEWORK_COREFOUNDATION, 1, [Have -framework CoreFoundation])
   AC_MSG_RESULT(yes)
else
   AC_MSG_RESULT(no)
fi
AM_CONDITIONAL(FRAMEWORK_COREFOUNDATION, test "$rk_cv_framework_corefoundation" = yes)
])
