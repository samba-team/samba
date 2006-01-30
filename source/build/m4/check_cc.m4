dnl SMB Build Environment CC Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

# don't let the AC_PROG_CC macro auto set the CFLAGS
OLD_CFLAGS="${CFLAGS}"
AC_PROG_CC
CFLAGS="${OLD_CFLAGS}"
if test x"$CC" = x""; then
	AC_MSG_WARN([No c compiler was not found!])
	AC_MSG_ERROR([Please Install gcc from http://gcc.gnu.org/])
fi

#
# Set the debug symbol option if we have
# --enable-*developer or --enable-debug
# and the compiler supports it
#
if test x$ac_cv_prog_cc_g = xyes -a x$debug = xyes; then
	CFLAGS="${CFLAGS} -g"
fi

dnl needed before AC_TRY_COMPILE
AC_ISC_POSIX

dnl Check if C compiler understands -c and -o at the same time
AC_PROG_CC_C_O
if eval "test \"`echo '$ac_cv_prog_cc_'${ac_cc}_c_o`\" = no"; then
	BROKEN_CC=yes
else
	BROKEN_CC=no
fi
AC_SUBST(BROKEN_CC)

AC_CACHE_CHECK([that the C compiler can precompile header files],samba_cv_precompiled_headers, [
	dnl Check whether the compiler can generate precompiled headers
	touch conftest.h
	if ${CC-cc} conftest.h 2> /dev/null && test -f conftest.h.gch; then
		samba_cv_precompiled_headers=yes
	else
		samba_cv_precompiled_headers=no
	fi])
PCH_AVAILABLE="#"
if test x"$samba_cv_precompiled_headers" = x"yes"; then
	PCH_AVAILABLE=""
fi
AC_SUBST(PCH_AVAILABLE)


dnl Check if the C compiler understands volatile (it should, being ANSI).
AC_CACHE_CHECK([that the C compiler understands volatile],samba_cv_volatile, [
	AC_TRY_COMPILE([#include <sys/types.h>],[volatile int i = 0],
		samba_cv_volatile=yes,samba_cv_volatile=no)])
if test x"$samba_cv_volatile" = x"yes"; then
	AC_DEFINE(HAVE_VOLATILE, 1, [Whether the C compiler understands volatile])
fi

############################################
# check if the compiler can do immediate structures
AC_CACHE_CHECK([for immediate structures],samba_cv_immediate_structures, [
    AC_TRY_COMPILE([
#include <stdio.h>],
[
   typedef struct {unsigned x;} FOOBAR;
   #define X_FOOBAR(x) ((FOOBAR) { x })
   #define FOO_ONE X_FOOBAR(1)
   FOOBAR f = FOO_ONE;   
   static struct {
	FOOBAR y; 
	} f2[] = {
		{FOO_ONE}
	};   
],
	samba_cv_immediate_structures=yes,samba_cv_immediate_structures=no)])
if test x"$samba_cv_immediate_structures" = x"yes"; then
   AC_DEFINE(HAVE_IMMEDIATE_STRUCTURES,1,[Whether the compiler supports immediate structures])
fi

############################################
# check if the compiler handles c99 struct initialization
SMB_CC_SUPPORTS_C99_STRUCT_INIT(samba_cv_c99_struct_initialization=yes,
		    samba_cv_c99_struct_initialization=no)

if test x"$samba_cv_c99_struct_initialization" != x"yes"; then
	# We might need to add some flags to CC to get c99 behaviour.
	AX_CFLAGS_IRIX_OPTION(-c99, CFLAGS)
	SMB_CC_SUPPORTS_C99_STRUCT_INIT(samba_cv_c99_struct_initialization=yes,
			    samba_cv_c99_struct_initialization=no)
fi

if test x"$samba_cv_c99_struct_initialization" != x"yes"; then
	AC_MSG_WARN([C compiler does not support c99 struct initialization!])
	AC_MSG_ERROR([Please Install gcc from http://gcc.gnu.org/])
fi

############################################
# check if the compiler can handle negative enum values
AC_CACHE_CHECK([that the C compiler understands negative enum values],SMB_BUILD_CC_NEGATIVE_ENUM_VALUES, [
    AC_TRY_COMPILE([
#include <stdio.h>],
[
	enum negative_values { NEGATIVE_VALUE = 0xFFFFFFFF };
],
	SMB_BUILD_CC_NEGATIVE_ENUM_VALUES=yes,SMB_BUILD_CC_NEGATIVE_ENUM_VALUES=no)])
if test x"$SMB_BUILD_CC_NEGATIVE_ENUM_VALUES" != x"yes"; then
	AC_MSG_WARN([using --unit-enums for pidl])
	PIDL_ARGS="$PIDL_ARGS --uint-enums"
fi

AC_MSG_CHECKING([for test routines])
AC_TRY_RUN([#include "${srcdir-.}/build/tests/trivial.c"],
	    AC_MSG_RESULT(yes),
	    AC_MSG_ERROR([cant find test code. Aborting config]),
	    AC_MSG_WARN([cannot run when cross-compiling]))

#
# Check if the compiler support ELF visibility for symbols
#
if test x"$GCC" = x"yes" ; then
    AX_CFLAGS_GCC_OPTION([-fvisibility=hidden], VISIBILITY_CFLAGS)
fi
if test -n "$VISIBILITY_CFLAGS"; then
	OLD_CFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} ${VISIBILITY_CFLAGS} -D_PUBLIC_=__attribute__((visibility(\"default\")))"
	VISIBILITY_CFLAGS="${VISIBILITY_CFLAGS} -D_PUBLIC_=\"__attribute__((visibility(\\\"default\\\")))\""
	AC_MSG_CHECKING([that the C compiler can use the VISIBILITY_CFLAGS])
	AC_TRY_RUN([
		_PUBLIC_ void vis_foo1(void) {}
		__attribute__((visibility("default"))) void vis_foo2(void) {}
		#include "${srcdir-.}/build/tests/trivial.c"
		], AC_MSG_RESULT(yes), [AC_MSG_RESULT(no);VISIBILITY_CFLAGS=""])
	CFLAGS="${OLD_CFLAGS}"
fi

#
# Check if the compiler can handle the options we selected by
# --enable-*developer
#
DEVELOPER_CFLAGS=""
if test x$developer = xyes; then
    	OLD_CFLAGS="${CFLAGS}"

	CFLAGS="${CFLAGS} -D_SAMBA_DEVELOPER_DONNOT_USE_O2_"
	DEVELOPER_CFLAGS="-DDEBUG_PASSWORD -DDEVELOPER"
	if test x"$GCC" = x"yes" ; then
	    AX_CFLAGS_GCC_OPTION(-Wall, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wshadow, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Werror-implicit-function-declaration, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wstrict-prototypes, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wpointer-arith, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wcast-qual, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wcast-align, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wwrite-strings, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wmissing-format-attribute, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wformat=2, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wno-format-y2k, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wno-declaration-after-statement, DEVELOPER_CFLAGS)
	else
	    AX_CFLAGS_IRIX_OPTION(-fullwarn, DEVELOPER_CFLAGS)
	fi

    	CFLAGS="${OLD_CFLAGS}"
fi
if test -n "$DEVELOPER_CFLAGS"; then
	OLD_CFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} ${DEVELOPER_CFLAGS}"
	AC_MSG_CHECKING([that the C compiler can use the DEVELOPER_CFLAGS])
	AC_TRY_RUN([#include "${srcdir-.}/build/tests/trivial.c"],
		AC_MSG_RESULT(yes),
		DEVELOPER_CFLAGS=""; AC_MSG_RESULT(no))
	CFLAGS="${OLD_CFLAGS}"
fi

# allow for --with-hostcc=gcc
AC_ARG_WITH(hostcc,[  --with-hostcc=compiler    choose host compiler],
[HOSTCC=$withval],
[
if test z"$cross_compiling" = "yes"; then 
	HOSTCC=cc
else 
	HOSTCC=$CC
fi
])
AC_SUBST(HOSTCC)

AC_PATH_PROG(GCOV,gcov)
