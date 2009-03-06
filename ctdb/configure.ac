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

case `uname` in
  Linux*)
    CTDB_SYSTEM_OBJ=common/system_linux.o
    CTDB_SCSI_IO=bin/scsi_io
    CTDB_PCAP_LDFLAGS=
    ;;
  AIX*)
    CTDB_SYSTEM_OBJ=common/system_aix.o
    CTDB_SCSI_IO=
    CTDB_PCAP_LDFLAGS=-lpcap
    ;;
  *)
    echo unknown system  cant configure
    exit
    ;;
esac

AC_LIBREPLACE_ALL_CHECKS

if test "$ac_cv_prog_gcc" = yes; then
   CFLAGS="$CFLAGS -Wall -Wshadow -Wstrict-prototypes -Wpointer-arith -Wcast-qual -Wcast-align -Wwrite-strings"
fi

LOGDIR='${localstatedir}/log'
AC_ARG_WITH([logdir],
	[  --with-logdir=DIR       path to log directory [[LOCALSTATEDIR/log]]],
	LOGDIR=$withval)
if test ! -z "$LOGDIR"; then
  if test "$LOGDIR" = "yes" -o "$LOGDIR" = "no"; then
    AC_MSG_ERROR([--with-logdir must specify a path])
  fi
fi
AC_SUBST(LOGDIR)

AC_CONFIG_HEADER(config.h)

EXTRA_OBJ=""

m4_include(libpopt.m4)
m4_include(libtalloc.m4)
m4_include(libtdb.m4)
m4_include(libevents.m4)
m4_include(ib/config.m4)

AC_CHECK_HEADERS(libipq.h linux/netfilter.h)

IPQ_LIBS=""
if test x"$ac_cv_header_libipq_h" = x"yes"; then
   IPQ_LIBS="-lipq"
fi
AC_SUBST(IPQ_LIBS)

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
AC_SUBST(CTDB_SYSTEM_OBJ)
AC_SUBST(CTDB_SCSI_IO)
AC_SUBST(CTDB_PCAP_LDFLAGS)

AC_OUTPUT(Makefile)
