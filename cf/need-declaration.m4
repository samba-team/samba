dnl $Id$
dnl
dnl
dnl Check if we need the declaration of a variable
dnl

AC_DEFUN(AC_NEED_DECLARATION, [
AC_MSG_CHECKING([if $3 needs a declaration])
AC_CACHE_VAL(ac_cv_var_$3_declaration, [
AC_TRY_COMPILE([$1],
[$2 foo = ($2)$3; ],
eval "ac_cv_var_$3_declaration=no",
eval "ac_cv_var_$3_declaration=yes")
])

changequote(, )dnl
eval "ac_tr_var=NEED_`echo $3 | tr '[a-z]' '[A-Z]'`_DECLARATION"
changequote([, ])dnl

define([foo], [NEED_]translit($3, [a-z], [A-Z])[_DECLARATION])
: << END
@@@syms="$syms foo"@@@
END
undefine([foo])

AC_MSG_RESULT($ac_cv_var_$3_declaration)
if eval "test \"\$ac_cv_var_$3_declaration\" = yes"; then
	AC_DEFINE_UNQUOTED($ac_tr_var)
fi
])
