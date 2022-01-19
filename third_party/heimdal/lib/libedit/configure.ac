#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.
#
# Compile with debug symbols:
#    CFLAGS="-ggdb -pedandic -O0" ./configure
#    CFLAGS="-ggdb -Wall -Wextra -pedantic -O0" ./configure
#
# Verbose output can be enabled with
#    "./configure --disable-silent-rules" or "make V=1"
#

AC_PREREQ(2.61)
AC_INIT(libedit, [EL_RELEASE],, libedit-[EL_TIMESTAMP])
AC_CONFIG_SRCDIR([src/el.c])
AC_CONFIG_HEADER([config.h])

# features of Posix that are extensions to C (define _GNU_SOURCE)
AC_USE_SYSTEM_EXTENSIONS

AM_INIT_AUTOMAKE
AM_MAINTAINER_MODE
AC_PROG_LIBTOOL

# libtool -version-info
AC_SUBST(LT_VERSION, [0:36:0])

m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES([yes])])

# Checks for programs.
AC_PROG_CC_C99
#AC_PROG_CC
AC_PROG_LN_S
AC_PROG_AWK
EL_MANTYPE


AC_CHECK_LIB(curses, tgetent,,
   [AC_CHECK_LIB(ncurses, tgetent,,
      [AC_CHECK_LIB(tinfo, tgetent,,
         [AC_MSG_ERROR([libcurses, libncurses, or tinfo are required!])] )] )] )


# Checks for header files.
AC_HEADER_DIRENT
AC_HEADER_STDC
AC_HEADER_SYS_WAIT
AC_CHECK_HEADERS([fcntl.h limits.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h unistd.h curses.h ncurses.h sys/cdefs.h])

AC_CHECK_HEADER([termios.h], [], [AC_MSG_ERROR([termios.h is required!])],[])

## include curses.h to prevent "Present But Cannot Be Compiled"
AC_CHECK_HEADERS([term.h],,,
[[#if HAVE_CURSES_H
# include <curses.h>
#elif HAVE_NCURSES_H
# include <ncurses.h>
#endif
]])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_CHECK_TYPES([u_int32_t])

AC_TRY_COMPILE([
#include <limits.h>
#include <stddef.h>
#if HAVE_STDINT_H
# include <stdint.h>
#endif
],
[size_t x = SIZE_MAX;],
[have_size_max=yes],
[have_size_max=no])
if test "$have_size_max" = yes; then
    AC_DEFINE([HAVE_SIZE_MAX], [1],
              [Define to 1 if if your system has SIZE_MAX])
fi

# Checks for library functions.
AC_FUNC_FORK
AC_PROG_GCC_TRADITIONAL
## _AIX is offended by rpl_malloc and rpl_realloc
#AC_FUNC_MALLOC
#AC_FUNC_REALLOC
AC_TYPE_SIGNAL
AC_FUNC_STAT
AC_CHECK_FUNCS([getline isascii issetugid wcsdup])
EL_GETPW_R_POSIX
EL_GETPW_R_DRAFT

AC_CHECK_MEMBER(struct dirent.d_namlen,
AC_DEFINE([HAVE_STRUCT_DIRENT_D_NAMLEN],[1],
[Define to 1 if struct dirent has member d_namlen]),,
[#if HAVE_DIRENT_H
#include <dirent.h>
#endif
])

AH_BOTTOM([
#include "sys.h"
#define SCCSID
#undef LIBC_SCCS
#define lint
])

AC_CONFIG_FILES([Makefile
                 src/Makefile
])
AC_OUTPUT
