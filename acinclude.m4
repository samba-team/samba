dnl
dnl $Id$
dnl

dnl
dnl General tests
dnl

dnl
dnl Look for function in any of the specified libraries
dnl

AC_DEFUN(AC_FIND_FUNC_NO_LIBS, [

AC_MSG_CHECKING([for $1])
AC_CACHE_VAL(ac_cv_funclib_$1,
[
if eval "test \"\$ac_cv_func_$1\" != yes" ; then
	ac_save_LIBS="$LIBS"
	for ac_lib in "" $2; do
		if test -n "$ac_lib"; then 
			ac_lib="-l$ac_lib"
			LIBS="$ac_lib $ac_save_LIBS"
		fi
		AC_TRY_LINK([],[$1()],eval "if test -n \"$ac_lib\";then ac_cv_funclib_$1=$ac_lib; else ac_cv_funclib_$1=yes; fi";break)
	done
	eval "ac_cv_funclib_$1=\${ac_cv_funclib_$1-no}"
	LIBS="$ac_save_LIBS"
fi
])

eval "ac_res=\$ac_cv_funclib_$1"

# autoheader tricks *sigh*
: << END
@@@funcs="$funcs $1"@@@
@@@libs="$libs $2"@@@
END

changequote(, )dnl
eval "ac_tr_func=HAVE_`echo $1 | tr '[a-z]' '[A-Z]'`"
eval "ac_tr_lib=HAVE_LIB`echo $ac_res | sed -e 's/-l//' | tr '[a-z]' '[A-Z]'`"
eval "LIB_$1=$ac_res"
changequote([, ])dnl

case "$ac_res" in
	yes)
	eval "ac_cv_func_$1=yes"
	eval "LIB_$1="
	AC_DEFINE_UNQUOTED($ac_tr_func)
	AC_MSG_RESULT([yes])
	;;
	no)
	eval "ac_cv_func_$1=no"
	eval "LIB_$1="
	AC_MSG_RESULT([no])
	;;
	*)
	eval "ac_cv_func_$1=yes"
	eval "ac_cv_lib_`echo "$ac_res" | sed 's/-l//'`=yes"
	AC_DEFINE_UNQUOTED($ac_tr_func)
	AC_DEFINE_UNQUOTED($ac_tr_lib)
	AC_MSG_RESULT([yes, in $ac_res])
	;;
esac
AC_SUBST(LIB_$1)
])

AC_DEFUN(AC_FIND_FUNC, [
AC_FIND_FUNC_NO_LIBS($1, $2)
if test -n "$LIB_$1"; then
	LIBS="$LIBS $LIB_$1"
fi
])

dnl
dnl Same as AC _REPLACE_FUNCS, just define HAVE_func if found in normal
dnl libraries 

AC_DEFUN(AC_BROKEN,
[for ac_func in $1
do
AC_CHECK_FUNC($ac_func, [
changequote(, )dnl
ac_tr_func=HAVE_`echo $ac_func | tr '[a-z]' '[A-Z]'`
changequote([, ])dnl
AC_DEFINE_UNQUOTED($ac_tr_func)],[LIBOBJS="$LIBOBJS ${ac_func}.o"])
# autoheader tricks *sigh*
: << END
@@@funcs="$funcs $1"@@@
END
done
AC_SUBST(LIBOBJS)dnl
])

dnl
dnl Mix between AC_FIND_FUNC and AC_BROKEN
dnl

AC_DEFUN(AC_FIND_IF_NOT_BROKEN,
[AC_FIND_FUNC($1, $2)
if eval "test \"$ac_cv_func_$1\" != yes"; then
LIBOBJS="$LIBOBJS $1.o"
fi
AC_SUBST(LIBOBJS)dnl
])

dnl
dnl Build S/Key support into the login program.
dnl
AC_DEFUN(AC_TEST_SKEY,
[AC_ARG_WITH(skeylib,
[  --with-skeylib=dir      use the skeylib.a in dir],
)
test -n "$with_skeylib" && 
SKEYLIB="-L$with_skeylib -lskey" &&
SKEYINCLUDE="-I$with_skeylib" &&
AC_MSG_RESULT(Using skeylib in $with_skeylib)
AC_SUBST(SKEYLIB)
AC_SUBST(SKEYINCLUDE)
test -n "$with_skeylib" &&
AC_DEFINE(SKEY)])

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

dnl
dnl Check if we need the prototype for a function
dnl

AC_DEFUN(AC_NEED_PROTO, [
AC_MSG_CHECKING([if $3 needs a proto])
AC_CACHE_VAL(ac_cv_func_$3_proto, [
AC_TRY_COMPILE([$1],
[$2],
eval "ac_cv_func_$3_proto=no",
eval "ac_cv_func_$3_proto=yes")
])
changequote(, )dnl
eval "ac_tr_func=NEED_`echo $3 | tr '[a-z]' '[A-Z]'`_PROTO"
changequote([, ])dnl

define([foo], [NEED_]translit($3, [a-z], [A-Z])[_PROTO])
: << END
@@@syms="$syms foo"@@@
END
undefine([foo])

AC_MSG_RESULT($ac_cv_func_$3_proto)
if eval "test \"\$ac_cv_func_$3_proto\" = yes"; then
	AC_DEFINE_UNQUOTED($ac_tr_func)
fi
])

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
eval "ac_tr_var=HAVE_STRUCT_`echo $2 | tr '[a-z]' '[A-Z]'`_`echo $4 | tr '[a-z]' '[A-Z]'`"
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

dnl
dnl Specific tests
dnl

dnl
dnl We prefer byacc or yacc because they do not use `alloca'
dnl

AC_DEFUN(AC_KRB_PROG_YACC,
[AC_CHECK_PROGS(YACC, byacc yacc 'bison -y')])

dnl
dnl NEXTSTEP is not posix compliant by default,
dnl you need a switch -posix to the compiler
dnl

AC_DEFUN(AC_KRB_SYS_NEXTSTEP, [
AC_MSG_CHECKING(for NEXTSTEP)
AC_CACHE_VAL(krb_cv_sys_nextstep,
AC_EGREP_CPP(yes, 
[#ifdef NeXT
	yes
#endif 
], krb_cv_sys_nextstep=yes, krb_cv_sys_nextstep=no) )
if test "$krb_cv_sys_nextstep" = "yes"; then
  CFLAGS="$CFLAGS -posix"
  LIBS="$LIBS -posix"
fi
AC_MSG_RESULT($krb_cv_sys_nextstep)
])

dnl
dnl AIX have a very different syscall convention
dnl
AC_DEFUN(AC_KRB_SYS_AIX, [
AC_MSG_CHECKING(for AIX)
AC_CACHE_VAL(krb_cv_sys_aix,
AC_EGREP_CPP(yes, 
[#ifdef _AIX
	yes
#endif 
], krb_cv_sys_aix=yes, krb_cv_sys_aix=no) )
AC_MSG_RESULT($krb_cv_sys_aix)
])

dnl
dnl test for broken getcwd in (SunOS braindamage)
dnl

AC_DEFUN(AC_KRB_FUNC_GETCWD_BROKEN, [
if test "$ac_cv_func_getcwd" = yes; then
AC_MSG_CHECKING(if getcwd is broken)
AC_CACHE_VAL(ac_cv_func_getcwd_broken, [
ac_cv_func_getcwd_broken=no

AC_TRY_RUN([
#include <errno.h>
char *getcwd(char*, int);

void *popen(char *cmd, char *mode)
{
	errno = ENOTTY;
	return 0;
}

int main()
{
	char *ret;
	ret = getcwd(0, 1024);
	if(ret == 0 && errno == ENOTTY)
		return 0;
	return 1;
}
], ac_cv_func_getcwd_broken=yes,:,:)
])
if test "$ac_cv_func_getcwd_broken" = yes; then
	AC_DEFINE(BROKEN_GETCWD, 1)dnl
	LIBOBJS="$LIBOBJS getcwd.o"
	AC_SUBST(LIBOBJS)dnl
	AC_MSG_RESULT($ac_cv_func_getcwd_broken)
else
	AC_MSG_RESULT([seems ok])
fi
fi
])


AC_DEFUN(AC_HAVE_PRAGMA_WEAK, [
if test "${with_shared}" = "yes"; then
AC_MSG_CHECKING(for pragma weak)
AC_CACHE_VAL(ac_have_pragma_weak, [
ac_have_pragma_weak=no
cat > conftest_foo.$ac_ext <<'EOF'
[#]line __oline__ "configure"
#include "confdefs.h"
#pragma weak foo = _foo
int _foo = 17;
EOF
cat > conftest_bar.$ac_ext <<'EOF'
[#]line __oline__ "configure"
#include "confdefs.h"
extern int foo;

int t() {
  return foo;
}

int main() {
  return t();
}
EOF
if AC_TRY_EVAL('CC $CFLAGS $CPPFLAGS $LDFLAGS conftest_foo.$ac_ext conftest_bar.$ac_ext -o conftest'); then
ac_have_pragma_weak=yes
fi
rm -rf conftest*
if test "$ac_have_pragma_weak" = "yes"; then
	AC_DEFINE(HAVE_PRAGMA_WEAK, 1)dnl
fi
AC_MSG_RESULT($ac_have_pragma_weak)
fi
])
])

AC_DEFUN(AC_GROK_TYPE, [
AC_CACHE_VAL(ac_cv_type_$1, 
AC_TRY_COMPILE([
#include "confdefs.h"
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_BITYPES_H
#include <sys/bitypes.h>
#endif
],
$i x;
,
eval ac_cv_type_$1=yes,
eval ac_cv_type_$1=no))])


AC_DEFUN(AC_GROK_TYPES, [
for i in $1; do
	AC_MSG_CHECKING(for $i)
	AC_GROK_TYPE($i)
	eval ac_res=\$ac_cv_type_$i
	if test "$ac_res" = yes; then
		type=HAVE_`echo $i | tr '[a-z]' '[A-Z]'`
		AC_DEFINE_UNQUOTED($type)
	fi
	AC_MSG_RESULT($ac_res)
done
])

dnl
dnl Check for the variable `timezone'
dnl

AC_DEFUN(AC_KRB_VAR_TIMEZONE, [
AC_MSG_CHECKING(for variable timezone)
AC_CACHE_VAL(ac_krb_var_timezone,
AC_TRY_LINK([#include <time.h>], [int foo = timezone;],
ac_krb_var_timezone=yes,ac_krb_var_timezone=no))
AC_MSG_RESULT($ac_krb_var_timezone)
if test "$ac_krb_var_timezone" = yes; then
  AC_DEFINE_UNQUOTED(HAVE_TIMEZONE)
fi
])
