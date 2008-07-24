dnl $Id$
dnl
dnl Tests for readline functions
dnl

dnl el_init

AC_DEFUN([KRB_READLINE],[
AC_FIND_FUNC_NO_LIBS(el_init, edit, [], [], [$LIB_tgetent])
if test "$ac_cv_func_el_init" = yes ; then
	AC_CACHE_CHECK(for four argument el_init, ac_cv_func_el_init_four,[
		AC_COMPILE_IFELSE([AC_LANG_PROGRAM([[#include <stdio.h>
			#include <histedit.h>]],
			[[el_init("", NULL, NULL, NULL);]])],
			[ac_cv_func_el_init_four=yes],
			[ac_cv_func_el_init_four=no])])
	if test "$ac_cv_func_el_init_four" = yes; then
		AC_DEFINE(HAVE_FOUR_VALUED_EL_INIT, 1, [Define if el_init takes four arguments.])
	fi
fi

dnl readline

ac_foo=no
build_editline=no
if test "$with_readline" = yes; then
	:
elif test "$ac_cv_func_readline" = yes; then
	:
elif test "$ac_cv_func_el_init" = yes; then
	ac_foo=yes
	build_editline=yes
	LIB_readline="\$(top_builddir)/lib/editline/libel_compat.la \$(LIB_el_init) \$(LIB_tgetent)"
else
	build_editline=yes
	LIB_readline="\$(top_builddir)/lib/editline/libeditline.la \$(LIB_tgetent)"
fi
AM_CONDITIONAL(EDITLINE, test "$build_editline" = yes)
AM_CONDITIONAL(el_compat, test "$ac_foo" = yes)
AC_DEFINE(HAVE_READLINE, 1, 
	[Define if you have a readline compatible library.])dnl

])
