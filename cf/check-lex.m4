#
# XXX remove this when we get autoconf 2.61
#


# This file is part of Autoconf.                       -*- Autoconf -*-
# Checking for programs.

# Copyright (C) 1992, 1993, 1994, 1995, 1996, 1998, 1999, 2000, 2001,
# 2002, 2003, 2004, 2005, 2006 Free Software Foundation, Inc.

# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
# 02110-1301, USA.

# As a special exception, the Free Software Foundation gives unlimited
# permission to copy, distribute and modify the configure scripts that
# are the output of Autoconf.  You need not follow the terms of the GNU
# General Public License when using or distributing such scripts, even
# though portions of the text of Autoconf appear in them.  The GNU
# General Public License (GPL) does govern all other use of the material
# that constitutes the Autoconf program.
#
# Certain portions of the Autoconf source text are designed to be copied
# (in certain cases, depending on the input) into the output of
# Autoconf.  We call these the "data" portions.  The rest of the Autoconf
# source text consists of comments plus executable code that decides which
# of the data portions to output in any given case.  We call these
# comments and executable code the "non-data" portions.  Autoconf never
# copies any of the non-data portions into its output.
#
# This special exception to the GPL applies to versions of Autoconf
# released by the Free Software Foundation.  When you make and
# distribute a modified version of Autoconf, you may extend this special
# exception to the GPL to apply to your modified version as well, *unless*
# your modified version has the potential to copy into its output some
# of the text that was the non-data portion of the version that you started
# with.  (In other words, unless your change moves or copies text from
# the non-data portions to the data portions.)  If your modification has
# such potential, you must delete any notice of this special exception
# to the GPL from your modified version.
#
# Written by David MacKenzie, with help from
# Franc,ois Pinard, Karl Berry, Richard Pixley, Ian Lance Taylor,
# Roland McGrath, Noah Friedman, david d zuhn, and many others.


# AC_PROG_LEX
# -----------
# Look for flex or lex.  Set its associated library to LEXLIB.
# Check if lex declares yytext as a char * by default, not a char[].
AN_MAKEVAR([LEX],  [AC_PROG_LEX])
AN_PROGRAM([lex],  [AC_PROG_LEX])
AN_PROGRAM([flex], [AC_PROG_LEX])
AC_DEFUN_ONCE([AC_PROG_LEX],
[AC_CHECK_PROGS(LEX, flex lex, :)
if test "x$LEX" != "x:"; then
  _AC_PROG_LEX_YYTEXT_DECL
fi])


# _AC_PROG_LEX_YYTEXT_DECL
# ------------------------
# Check for the Lex output root, the Lex library, and whether Lex
# declares yytext as a char * by default.
m4_define([_AC_PROG_LEX_YYTEXT_DECL],
[cat >conftest.l <<_ACEOF[
%%
a { ECHO; }
b { REJECT; }
c { yymore (); }
d { yyless (1); }
e { yyless (input () != 0); }
f { unput (yytext[0]); }
. { BEGIN INITIAL; }
%%
#ifdef YYTEXT_POINTER
extern char *yytext;
#endif
int
main (void)
{
  return ! yylex () + ! yywrap ();
}
]_ACEOF
_AC_DO_VAR(LEX conftest.l)
AC_CACHE_CHECK([lex output file root], [ac_cv_prog_lex_root], [
if test -f lex.yy.c; then
  ac_cv_prog_lex_root=lex.yy
elif test -f lexyy.c; then
  ac_cv_prog_lex_root=lexyy
else
  AC_MSG_ERROR([cannot find output from $LEX; giving up])
fi])
AC_SUBST([LEX_OUTPUT_ROOT], [$ac_cv_prog_lex_root])dnl

if test -z "${LEXLIB+set}"; then
  AC_CACHE_CHECK([lex library], [ac_cv_lib_lex], [
    ac_save_LIBS=$LIBS
    ac_cv_lib_lex='none needed'
    for ac_lib in '' -lfl -ll; do
      LIBS="$ac_lib $ac_save_LIBS"
      AC_LINK_IFELSE([`cat $LEX_OUTPUT_ROOT.c`], [ac_cv_lib_lex=$ac_lib])
      test "$ac_cv_lib_lex" != 'none needed' && break
    done
    LIBS=$ac_save_LIBS
  ])
  test "$ac_cv_lib_lex" != 'none needed' && LEXLIB=$ac_cv_lib_lex
fi
AC_SUBST(LEXLIB)

AC_CACHE_CHECK(whether yytext is a pointer, ac_cv_prog_lex_yytext_pointer,
[# POSIX says lex can declare yytext either as a pointer or an array; the
# default is implementation-dependent.  Figure out which it is, since
# not all implementations provide the %pointer and %array declarations.
ac_cv_prog_lex_yytext_pointer=no
ac_save_LIBS=$LIBS
LIBS="$LEXLIB $ac_save_LIBS"
AC_LINK_IFELSE(
  [#define YYTEXT_POINTER 1
`cat $LEX_OUTPUT_ROOT.c`],
  [ac_cv_prog_lex_yytext_pointer=yes])
LIBS=$ac_save_LIBS
])
dnl
if test $ac_cv_prog_lex_yytext_pointer = yes; then
  AC_DEFINE(YYTEXT_POINTER, 1,
	    [Define to 1 if `lex' declares `yytext' as a `char *' by default,
	     not a `char[]'.])
fi
rm -f conftest.l $LEX_OUTPUT_ROOT.c
])# _AC_PROG_LEX_YYTEXT_DECL


# Require AC_PROG_LEX in case some people were just calling this macro.
AU_DEFUN([AC_DECL_YYTEXT],  [AC_PROG_LEX])


