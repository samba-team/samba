AC_DEFUN([SMB_EXT_LIB], [echo -n ""])
AC_DEFUN([SMB_ENABLE], [echo -n ""])

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

dnl AC_SEARCH_LIBS_EXT(FUNCTION, SEARCH-LIBS, EXT_LIBS,
dnl                    [ACTION-IF-FOUND], [ACTION-IF-NOT-FOUND],
dnl                    [OTHER-LIBRARIES])
dnl --------------------------------------------------------
dnl Search for a library defining FUNC, if it's not already available.
AC_DEFUN([AC_SEARCH_LIBS_EXT],
[AC_CACHE_CHECK([for library containing $1], [ac_cv_search_ext_$1],
[
ac_func_search_ext_save_LIBS=$LIBS
ac_cv_search_ext_$1=no
AC_LINK_IFELSE([AC_LANG_CALL([], [$1])],
	       [ac_cv_search_ext_$1="none required"])
if test "$ac_cv_search_ext_$1" = no; then
  for ac_lib in $2; do
    LIBS="-l$ac_lib $$3 $6 $ac_func_search_save_ext_LIBS"
    AC_LINK_IFELSE([AC_LANG_CALL([], [$1])],
		   [ac_cv_search_ext_$1="-l$ac_lib"
break])
  done
fi
LIBS=$ac_func_search_ext_save_LIBS])
AS_IF([test "$ac_cv_search_ext_$1" != no],
  [test "$ac_cv_search_ext_$1" = "none required" || $3="$ac_cv_search_ext_$1 $$3"
  $4],
      [$5])dnl
])

AC_PREREQ(2.50)
AC_INIT(dlfcn.c)
AC_CONFIG_SRCDIR([dlfcn.c])
AC_CONFIG_HEADER(replace_config.h)
AC_PROG_INSTALL
sinclude(config.m4)
sinclude(win32/config.m4)
sinclude(repdir/config.m4)
AC_OUTPUT(Makefile)
