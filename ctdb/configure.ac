AC_PREREQ(2.50)
AC_INIT(ctdb, m4_esyscmd([grep 'Version:' ./packaging/RPM/ctdb.spec 2>/dev/null | head -1 | sed -e 's/[ \t]*Version:[ \t]*\([^ \t]*\)[ \t]*.*/\1/' | tr -d '\n']))
AC_DEFUN([SMB_MODULE_DEFAULT], [echo -n ""])
AC_DEFUN([SMB_LIBRARY_ENABLE], [echo -n ""])
AC_DEFUN([SMB_EXT_LIB], [echo -n ""])
AC_DEFUN([SMB_ENABLE], [echo -n ""])
AC_CONFIG_SRCDIR([server/ctdbd.c])

if test "${libdir}" = '${exec_prefix}/lib'; then
  case `uname -m` in
    x86_64|ppc64|powerpc64)
      libdir='${exec_prefix}/lib64'
      ;;
    *)
      libdir='${exec_prefix}/lib'
      ;;
  esac
fi

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
m4_include(lib/util/signal.m4)
m4_include(lib/util/fault.m4)

AC_CHECK_HEADERS(sched.h)
AC_CHECK_FUNCS(sched_setscheduler)
AC_CHECK_FUNCS(mlockall)

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

AC_OUTPUT(Makefile ctdb.pc)
