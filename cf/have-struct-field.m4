dnl $Id$
dnl
dnl check for fields in a structure
dnl
dnl AC_HAVE_STRUCT_FIELD(struct, field, headers)

AC_DEFUN(AC_HAVE_STRUCT_FIELD, [
AC_CACHE_CHECK([for $2 in $1], ac_cv_type_$1_$2,[
AC_TRY_COMPILE([$3],[$1 x; x.$2;],
ac_cv_type_$1_$2=yes,
ac_cv_type_$1_$2=no)])
if test "$ac_cv_type_$1_$2" = yes; then
	define(foo, [HAVE_STRUCT_]translit($1_$2, [a-z ], [A-Z_]))
	AC_DEFINE(foo, 1, [Define if $1 has field $2.])
	undefine(foo)
fi
AC_MSG_RESULT($ac_cv_type_$1_$2)
])
