dnl see if a declaration exists for a function or variable
dnl defines HAVE_function_DECL if it exists
dnl AC_HAVE_DECL(var, includes)
AC_DEFUN(AC_HAVE_DECL,
[
 AC_CACHE_CHECK([for $1 declaration],ac_cv_have_$1_decl,[
    AC_TRY_COMPILE([$2],[int i = (int)$1],
        ac_cv_have_$1_decl=yes,ac_cv_have_$1_decl=no)])
 if test x"$ac_cv_have_$1_decl" = x"yes"; then
    AC_DEFINE([HAVE_]translit([$1], [a-z], [A-Z])[_DECL],1,[Whether $1() is available])
 fi
])
