dnl $Id$
dnl
dnl
dnl Check if a particular struct has a particular field
dnl

dnl AC_HAVE_STRUCT_FIELD(includes, struct, type, field)
AC_DEFUN(AC_HAVE_STRUCT_FIELD, [
AC_MSG_CHECKING([if $2 has a field $4])
AC_CACHE_VAL(ac_cv_struct_$2_$4, [
AC_TRY_COMPILE([$1],
[struct $2 foo; $3 bar = foo.$4; ],
eval "ac_cv_struct_$2_$4=yes",
eval "ac_cv_struct_$2_$4=no")
])
changequote(, )dnl
eval "ac_tr_var=HAVE_STRUCT_[]upcase($2)_[]upcase($4)"
changequote([, ])dnl

define([foo], [[HAVE_STRUCT_]translit($2, [a-z], [A-Z])[_]translit($4, [a-z], [A-Z])])
: << END
@@@syms="$syms foo"@@@
END
undefine([foo])

AC_MSG_RESULT($ac_cv_struct_$2_$4)
if eval "test \"\$ac_cv_struct_$2_$4\" = yes"; then
	AC_DEFINE_UNQUOTED($ac_tr_var)
fi
])
