dnl $Id$
dnl
dnl AC_CHECK_VAR(includes, variable)
AC_DEFUN(AC_CHECK_VAR, [
AC_MSG_CHECKING(for $2)
AC_CACHE_VAL(ac_cv_var_$2, [
AC_TRY_LINK([extern int $2;
int foo() { return $2; }],
	    [foo()],
	    ac_cv_var_$2=yes, ac_cv_var_$2=no)
])
eval "ac_tr_var=[HAVE_]translit($2,[a-z],[A-Z])"

define([foo], [HAVE_]translit($2, [a-z], [A-Z]))
: << END
@@@syms="$syms foo"@@@
END
undefine([foo])

AC_MSG_RESULT(`eval echo \\$ac_cv_var_$2`)
if test `eval echo \\$ac_cv_var_$2` = yes; then
	AC_DEFINE_UNQUOTED($ac_tr_var)
	AC_CHECK_DECLARATION([$1],[$2])
fi
])
