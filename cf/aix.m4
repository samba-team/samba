dnl
dnl $Id$
dnl

AC_DEFUN(KRB_AIX,[

AC_ARG_ENABLE(dynamic-afs,
	AC_HELP_STRING([--disable-dynamic-afs],
		[do not use loaded AFS library with AIX]))

aix=no
case "$host" in 
*-*-aix3*)
	aix=3
	;;
*-*-aix4*|*-*-aix5*)
	aix=4
	;;
esac
AM_CONDITIONAL(AIX, test "$aix" != no)dnl
AM_CONDITIONAL(AIX4, test "$aix" = 4)
AM_CONDITIONAL(AIX_DYNAMIC_AFS, test "$enable_dynamic_afs" != no)dnl

AC_FIND_FUNC_NO_LIBS(dlopen, dl)

if test "$aix" != no; then
	if test "$enable_dynamic_afs" != no; then
		if test "$ac_cv_funclib_dlopen" = yes; then
			AIX_EXTRA_KAFS=
		elif test "$ac_cv_funclib_dlopen" != no; then
			AIX_EXTRA_KAFS="$ac_cv_funclib_dlopen"
		else
			AIX_EXTRA_KAFS=-lld
		fi
	else
		AIX_EXTRA_KAFS=
	fi
fi

AM_CONDITIONAL(HAVE_DLOPEN, test "$ac_cv_funclib_dlopen" != no)dnl
AC_SUBST(AIX_EXTRA_KAFS)dnl

])