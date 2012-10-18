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
  GNU/kFreeBSD)
    CTDB_SYSTEM_OBJ=common/system_kfreebsd.o
    CTDB_SCSI_IO=
    CTDB_PCAP_LDFLAGS=-lpcap
    ;;
  FreeBSD)
    CTDB_SYSTEM_OBJ=common/system_freebsd.o
    CTDB_SCSI_IO=
    CTDB_PCAP_LDFLAGS=-lpcap
    LDFLAGS="$LDFLAGS -L/usr/local/lib -lexecinfo"
    AC_SUBST(LDFLAGS)
    CPPFLAGS="$CPPFLAGS -I/usr/local/include -D_FREEBSD_=1"
    AC_SUBST(CPPFLAGS)
    ;;
  GNU)
    CTDB_SYSTEM_OBJ=common/system_gnu.o
    CTDB_SCSI_IO=
    CTDB_PCAP_LDFLAGS=-lpcap
    ;;
  *)
    echo unknown system  cant configure
    exit
    ;;
esac

AC_LIBREPLACE_ALL_CHECKS
AC_LIBREPLACE_NETWORK_CHECKS

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

SOCKPATH='/tmp/ctdb.socket'
AC_ARG_WITH([socketpath],
	[  --with-socketpath=FILE       path to CTDB daemon socket [[/tmp/ctdb.socket]]],
	SOCKPATH=$withval)
if test ! -z "$SOCKPATH"; then
  if test "$SOCKPATH" = "yes" -o "$SOCKPATH" = "no"; then
	  AC_MSG_ERROR([--with-socketpath must specify a file path])
  fi
fi
AC_SUBST(SOCKPATH)

AC_CONFIG_HEADER(config.h)

EXTRA_OBJ=""

m4_include(libpopt.m4)
m4_include(libtalloc.m4)
m4_include(libtdb.m4)
m4_include(libtevent.m4)
m4_include(ib/config.m4)
m4_include(lib/util/signal.m4)
m4_include(lib/util/fault.m4)
m4_include(lib/socket_wrapper/config.m4)

AC_CHECK_HEADERS(sched.h)
AC_CHECK_HEADERS(pcp/pmapi.h pcp/impl.h pcp/pmda.h, [], [],
[[#ifdef HAVE_PCP_PMAPI_H
# include <pcp/pmapi.h>
#endif
#ifdef HAVE_PCP_IMPL_H
# include <pcp/impl.h>
#endif
]])

AC_CHECK_DECL([ETIME], [],[AC_DEFINE([ETIME], ETIMEDOUT, [ETIME on non-supporting platforms])], [
#include <errno.h>
])

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

if test x"$ac_cv_header_pcp_pmda_h" = x"yes"; then
    CTDB_PMDA=bin/pmdactdb
    CTDB_PMDA_INSTALL=install_pmda
else
    CTDB_PMDA=
    CTDB_PMDA_INSTALL=
fi


AC_SUBST(EXTRA_OBJ)
AC_SUBST(CTDB_SYSTEM_OBJ)
AC_SUBST(CTDB_SCSI_IO)
AC_SUBST(CTDB_PCAP_LDFLAGS)
AC_SUBST(CTDB_PMDA)
AC_SUBST(CTDB_PMDA_INSTALL)

AC_OUTPUT(Makefile ctdb.pc)
