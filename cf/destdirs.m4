dnl
dnl $Id$
dnl

AC_DEFUN([rk_DESTDIRS], 
[
# This is done by AC_OUTPUT but we need the result here.
test "x$prefix" = xNONE && prefix=$ac_default_prefix
test "x$exec_prefix" = xNONE && exec_prefix='${prefix}'

for i in bin lib libexec sbin; do
	i=${i}dir
	foo=AS_TR_CPP($i)
	x="\$${i}"
	eval y="$x"
	while test "x$y" != "x$x"; do
		x="$y"
		eval y="$x"
	done
	AC_DEFINE_UNQUOTED($foo,"$x")
done
AH_BOTTOM([#undef BINDIR 
#undef LIBDIR
#undef LIBEXECDIR
#undef SBINDIR])
])