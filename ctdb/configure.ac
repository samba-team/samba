AC_PREREQ(2.50)
AC_DEFUN([AC_CHECK_LIB_EXT], [
	AC_CHECK_LIB([$1],[$3],[$4],[$5],[$7])
	ac_cv_lib_ext_$1_$3=$ac_cv_lib_$1_$3
])
AC_DEFUN([AC_CHECK_FUNC_EXT], [
	AC_CHECK_FUNC([$1],[$3],[$4])
	ac_cv_func_ext_$1=$ac_cv_func_$1
])
AC_DEFUN([SMB_MODULE_DEFAULT], [echo -n ""])
AC_DEFUN([SMB_LIBRARY_ENABLE], [echo -n ""])
AC_DEFUN([SMB_EXT_LIB], [echo -n ""])
AC_DEFUN([SMB_ENABLE], [echo -n ""])
AC_INIT(ctdb.h)
AC_CONFIG_SRCDIR([server/ctdbd.c])

AC_LIBREPLACE_ALL_CHECKS

if test "$ac_cv_prog_gcc" = yes; then
   CFLAGS="$CFLAGS -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings"
fi

AC_CONFIG_HEADER(config.h)

EXTRA_OBJ=""

m4_include(libpopt.m4)
m4_include(libtalloc.m4)
m4_include(libtdb.m4)
m4_include(libevents.m4)
m4_include(ib/config.m4)

AC_CHECK_HEADERS(sched.h)
AC_CHECK_FUNCS(sched_setscheduler)

AC_CACHE_CHECK([for sin_len in sock],ctdb_cv_HAVE_SOCK_SIN_LEN,[
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>],
[struct sockaddr_in sock; sock.sin_len = sizeof(sock);],
ctdb_cv_HAVE_SOCK_SIN_LEN=yes,ctdb_cv_HAVE_SOCK_SIN_LEN=no)])
if test x"$ctdb_cv_HAVE_SOCK_SIN_LEN" = x"yes"; then
    AC_DEFINE(HAVE_SOCK_SIN_LEN,1,[Whether the sockaddr_in struct has a sin_len property])
fi

AC_SUBST(EXTRA_OBJ)

AC_OUTPUT(Makefile)
