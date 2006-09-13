dnl SMB Build Environment CC Checks
dnl -------------------------------------------------------
dnl  Copyright (C) Stefan (metze) Metzmacher 2004
dnl  Released under the GNU GPL
dnl -------------------------------------------------------
dnl

AC_LIBREPLACE_CC_CHECKS

if test x"$GCC" = x"yes" ; then
	AC_MSG_CHECKING([for version of gcc])
	GCC_VERSION=`$CC -dumpversion`
	AC_MSG_RESULT(${GCC_VERSION})
fi

#
# Set the debug symbol option if we have
# --enable-*developer or --enable-debug
# and the compiler supports it
#
if test x$ac_cv_prog_cc_g = xyes -a x$debug = xyes; then
	CFLAGS="${CFLAGS} -g"
fi

############################################
# check if the compiler handles c99 struct initialization
LIBREPLACE_C99_STRUCT_INIT(samba_cv_c99_struct_initialization=yes,
		    samba_cv_c99_struct_initialization=no)

if test x"$samba_cv_c99_struct_initialization" != x"yes"; then
	AC_MSG_WARN([C compiler does not support c99 struct initialization!])
	AC_MSG_ERROR([Please Install gcc from http://gcc.gnu.org/])
fi

############################################
# check if the compiler can handle negative enum values
# and don't truncate the values to INT_MAX
# a runtime test is needed here
AC_CACHE_CHECK([that the C compiler understands negative enum values],SMB_BUILD_CC_NEGATIVE_ENUM_VALUES, [
    AC_TRY_RUN(
[
	#include <stdio.h>
	enum negative_values { NEGATIVE_VALUE = 0xFFFFFFFF };
	int main(void) {
		enum negative_values v1 = NEGATIVE_VALUE;
		unsigned v2 = NEGATIVE_VALUE;

		if (v1 != 0xFFFFFFFF) {
			printf("%u != 0xFFFFFFFF\n", v1);
			return 1;
		}
		if (v2 != 0xFFFFFFFF) {
			printf("%u != 0xFFFFFFFF\n", v2);
			return 1;
		}

		return 0;
	}
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

visibility_attribute=no
VISIBILITY_CFLAGS=""
if test x"$GCC" = x"yes" ; then
	AX_CFLAGS_GCC_OPTION([-fvisibility=hidden], VISIBILITY_CFLAGS)
fi

if test -n "$VISIBILITY_CFLAGS"; then
	AC_MSG_CHECKING([whether the C compiler supports the visibility attribute])
	OLD_CFLAGS="$CFLAGS"

	CFLAGS="$CFLAGS $VISIBILITY_CFLAGS"
	AC_TRY_RUN([
		void vis_foo1(void) {}
		__attribute__((visibility("default"))) void vis_foo2(void) {}
		#include "${srcdir-.}/build/tests/trivial.c"
	],[
		AC_MSG_RESULT(yes)
		AC_DEFINE(HAVE_VISIBILITY_ATTR,1,[Whether the C compiler supports the visibility attribute])
		visibility_attribute=yes
	],[
		AC_MSG_RESULT(no)
	])
	CFLAGS="$OLD_CFLAGS"
fi
AC_SUBST(visibility_attribute)

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
	    #
	    # warnings we want...
	    #
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
	    AX_CFLAGS_GCC_OPTION(-Wdeclaration-after-statement, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wunused-macros, DEVELOPER_CFLAGS)
#	    AX_CFLAGS_GCC_OPTION(-Wextra, DEVELOPER_CFLAGS)
#	    AX_CFLAGS_GCC_OPTION(-Wc++-compat, DEVELOPER_CFLAGS)
#	    AX_CFLAGS_GCC_OPTION(-Wmissing-prototypes, DEVELOPER_CFLAGS)
#	    AX_CFLAGS_GCC_OPTION(-Wmissing-declarations, DEVELOPER_CFLAGS)
#	    AX_CFLAGS_GCC_OPTION(-Wmissing-field-initializers, DEVELOPER_CFLAGS)
	    #
	    # warnings we don't want...
	    #
	    AX_CFLAGS_GCC_OPTION(-Wno-format-y2k, DEVELOPER_CFLAGS)
	    AX_CFLAGS_GCC_OPTION(-Wno-unused-parameter, DEVELOPER_CFLAGS)
	else
	    AX_CFLAGS_IRIX_OPTION(-fullwarn, DEVELOPER_CFLAGS)
	fi

    	CFLAGS="${OLD_CFLAGS}"
fi
if test -n "$DEVELOPER_CFLAGS"; then
	OLD_CFLAGS="${CFLAGS}"
	CFLAGS="${CFLAGS} ${DEVELOPER_CFLAGS}"
	AC_MSG_CHECKING([that the C compiler can use the DEVELOPER_CFLAGS])
	AC_TRY_COMPILE([],[],
		AC_MSG_RESULT(yes),
		DEVELOPER_CFLAGS=""; AC_MSG_RESULT(no))
	CFLAGS="${OLD_CFLAGS}"
fi

#
# Config CPPFLAG settings for strange OS's that must be set
# before other tests.
#
case "$host_os" in
	# Try to work out if this is the native HPUX compiler that uses the -Ae flag.
	*hpux*)
		# mmap on HPUX is completely broken...
		AC_DEFINE(MMAP_BLACKLIST, 1, [Whether MMAP is broken])
		;;

	*aix*)
		if test "${GCC}" != "yes"; then
			## for funky AIX compiler using strncpy()
			CFLAGS="$CFLAGS -D_LINUX_SOURCE_COMPAT -qmaxmem=32000"
		fi
		;;

	#
	# VOS may need to have POSIX support and System V compatibility enabled.
	#
	*vos*)
		case "$CPPFLAGS" in
			*-D_POSIX_C_SOURCE*);;
			*)
				CPPFLAGS="$CPPFLAGS -D_POSIX_C_SOURCE=200112L"
				AC_DEFINE(_POSIX_C_SOURCE, 200112L, [Whether to enable POSIX support])
				;;
		esac
		case "$CPPFLAGS" in
			*-D_SYSV*|*-D_SVID_SOURCE*);;
			*)
				CPPFLAGS="$CPPFLAGS -D_SYSV"
				AC_DEFINE(_SYSV, 1, [Whether to enable System V compatibility])
				;;
		esac
		;;
esac

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

AC_PATH_PROG(MAKE,make)

AC_CACHE_CHECK([whether we have GNU make], samba_cv_gnu_make, [
if $ac_cv_path_MAKE --version | head -1 | grep GNU 2>/dev/null >/dev/null
then
	samba_cv_gnu_make=yes
else
	samba_cv_gnu_make=no
fi
])

GNU_MAKE=$samba_cv_gnu_make
AC_SUBST(GNU_MAKE)

if test "x$GNU_MAKE" = x"yes"; then
	AC_CACHE_CHECK([GNU make version], samba_cv_gnu_make_version,[
		samba_cv_gnu_make_version=`$ac_cv_path_MAKE --version | head -1 | cut -d " " -f 3 2>/dev/null`
	])
	GNU_MAKE_VERSION=$samba_cv_gnu_make_version
	AC_SUBST(GNU_MAKE_VERSION)
fi


new_make=no
AC_MSG_CHECKING([for GNU make >= 3.81])
if test x$GNU_MAKE = x"yes"; then
	if $PERL -e " \$_ = '$GNU_MAKE_VERSION'; s/@<:@^\d\.@:>@.*//g; exit (\$_ < 3.81);"; then
		new_make=yes
	fi
fi
AC_MSG_RESULT($new_make)
automatic_dependencies=no
AX_CFLAGS_GCC_OPTION([-M -MT conftest.d -MF conftest.o], [], [ automatic_dependencies=$new_make ], [])
AC_MSG_CHECKING([Whether to use automatic dependencies])
AC_MSG_RESULT($automatic_dependencies)
AC_SUBST(automatic_dependencies)
