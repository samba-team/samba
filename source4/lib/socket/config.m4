AC_CHECK_FUNCS(writev)
AC_CHECK_FUNCS(readv)

AC_CACHE_CHECK([for sin_len in sock],samba_cv_HAVE_SOCK_SIN_LEN,[
AC_TRY_COMPILE([#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>],
[struct sockaddr_in sock; sock.sin_len = sizeof(sock);],
samba_cv_HAVE_SOCK_SIN_LEN=yes,samba_cv_HAVE_SOCK_SIN_LEN=no)])
if test x"$samba_cv_HAVE_SOCK_SIN_LEN" = x"yes"; then
    AC_DEFINE(HAVE_SOCK_SIN_LEN,1,[Whether the sockaddr_in struct has a sin_len property])
fi

# The following test taken from the cvs sources
# If we can't find connect, try looking in -lsocket, -lnsl, and -linet.
# The Irix 5 libc.so has connect and gethostbyname, but Irix 5 also has
# libsocket.so which has a bad implementation of gethostbyname (it
# only looks in /etc/hosts), so we only look for -lsocket if we need
# it.
AC_CHECK_FUNCS(connect)
if test x"$ac_cv_func_connect" = x"no"; then
    AC_CHECK_LIB_EXT(nsl_s, SOCKET_LIBS, connect)
    AC_CHECK_LIB_EXT(nsl, SOCKET_LIBS, connect)
    AC_CHECK_LIB_EXT(socket, SOCKET_LIBS, connect)
    AC_CHECK_LIB_EXT(inet, SOCKET_LIBS, connect)
    SMB_ENABLE(EXT_SOCKET,YES)
    dnl We can't just call AC_CHECK_FUNCS(connect) here, because the value
    dnl has been cached.
    if test x"$ac_cv_lib_ext_nsl_s_connect" = x"yes" ||
       test x"$ac_cv_lib_ext_nsl_connect" = x"yes" ||
       test x"$ac_cv_lib_ext_socket_connect" = x"yes" ||
       test x"$ac_cv_lib_ext_inet_connect" = x"yes"; then
        AC_DEFINE(HAVE_CONNECT,1,[Whether the system has connect()])
    else
	AC_MSG_ERROR([no connect() function available!])
    fi
fi

SMB_EXT_LIB(EXT_SOCKET,[${SOCKET_LIBS}],[${SOCKET_CFLAGS}],[${SOCKET_CPPFLAGS}],[${SOCKET_LDFLAGS}])

AC_CHECK_FUNCS(gethostbyname)
if test x"$ac_cv_func_gethostbyname" = x"no"; then
    AC_CHECK_LIB_EXT(nsl_s, NSL_LIBS, gethostbyname)
    AC_CHECK_LIB_EXT(nsl, NSl_LIBS, gethostbyname)
    AC_CHECK_LIB_EXT(socket, NSL_LIBS, gethostbyname)
    SMB_ENABLE(EXT_NSL,YES)
    dnl We can't just call AC_CHECK_FUNCS(gethostbyname) here, because the value
    dnl has been cached.
    if test x"$ac_cv_lib_ext_nsl_s_gethostbyname" != x"yes" &&
       test x"$ac_cv_lib_ext_nsl_gethostbyname" != x"yes" &&
       test x"$ac_cv_lib_ext_socket_gethostbyname" != x"yes"; then
		AC_MSG_ERROR([no gethostbyname() function available!])
    fi
fi

SMB_EXT_LIB(EXT_NSL,[${NSL_LIBS}],[],[],[])

############################################
# check for unix domain sockets
AC_CACHE_CHECK([for unix domain sockets],samba_cv_unixsocket, [
    AC_TRY_COMPILE([
#include <sys/types.h>
#include <stdlib.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/un.h>],
[
  struct sockaddr_un sunaddr; 
  sunaddr.sun_family = AF_UNIX;
],
	samba_cv_unixsocket=yes,samba_cv_unixsocket=no)])
SMB_ENABLE(socket_unix, NO)
if test x"$samba_cv_unixsocket" = x"yes"; then
    SMB_ENABLE(socket_unix, YES)
    AC_DEFINE(HAVE_UNIXSOCKET,1,[If we need to build with unixscoket support])
fi

AC_CACHE_CHECK([for AF_LOCAL socket support], samba_cv_HAVE_WORKING_AF_LOCAL, [
AC_TRY_RUN([#include "${srcdir-.}/build/tests/unixsock.c"],
	   samba_cv_HAVE_WORKING_AF_LOCAL=yes,
	   samba_cv_HAVE_WORKING_AF_LOCAL=no,
	   samba_cv_HAVE_WORKING_AF_LOCAL=cross)])
if test x"$samba_cv_HAVE_WORKING_AF_LOCAL" != xno
then
    AC_DEFINE(HAVE_WORKING_AF_LOCAL, 1, [Define if you have working AF_LOCAL sockets])
fi

dnl test for ipv6 using the gethostbyname2() function. That should be sufficient
dnl for now
AC_CHECK_FUNCS(gethostbyname2, have_ipv6=true, have_ipv6=false)
SMB_ENABLE(socket_ipv6, NO)
if $have_ipv6 = true; then
    SMB_ENABLE(socket_ipv6, YES)
    AC_DEFINE(HAVE_IPV6,1,[Whether the system has ipv6 support])
fi
dnl don't build ipv6 by default, unless the above test enables it, or
dnl the configure uses --with-static-modules=socket_ipv6


##################
# look for a method of finding the list of network interfaces
#
# This tests need LIBS="$NSL_LIBS $SOCKET_LIBS"
#
old_LIBS=$LIBS
LIBS="$NSL_LIBS $SOCKET_LIBS"
iface=no;
AC_CACHE_CHECK([for iface AIX],samba_cv_HAVE_IFACE_AIX,[
AC_TRY_RUN([
#define HAVE_IFACE_AIX 1
#define AUTOCONF_TEST 1
#undef _XOPEN_SOURCE_EXTENDED
#include "${srcdir-.}/lib/socket/netif.c"],
           samba_cv_HAVE_IFACE_AIX=yes,samba_cv_HAVE_IFACE_AIX=no,samba_cv_HAVE_IFACE_AIX=cross)])
if test x"$samba_cv_HAVE_IFACE_AIX" = x"yes"; then
    iface=yes;AC_DEFINE(HAVE_IFACE_AIX,1,[Whether iface AIX is available])
fi

if test $iface = no; then
AC_CACHE_CHECK([for iface ifconf],samba_cv_HAVE_IFACE_IFCONF,[
AC_TRY_RUN([
#define HAVE_IFACE_IFCONF 1
#define AUTOCONF_TEST 1
#include "${srcdir-.}/lib/socket/netif.c"],
           samba_cv_HAVE_IFACE_IFCONF=yes,samba_cv_HAVE_IFACE_IFCONF=no,samba_cv_HAVE_IFACE_IFCONF=cross)])
if test x"$samba_cv_HAVE_IFACE_IFCONF" = x"yes"; then
    iface=yes;AC_DEFINE(HAVE_IFACE_IFCONF,1,[Whether iface ifconf is available])
fi
fi

if test $iface = no; then
AC_CACHE_CHECK([for iface ifreq],samba_cv_HAVE_IFACE_IFREQ,[
AC_TRY_RUN([
#define HAVE_IFACE_IFREQ 1
#define AUTOCONF_TEST 1
#include "${srcdir-.}/lib/socket/netif.c"],
           samba_cv_HAVE_IFACE_IFREQ=yes,samba_cv_HAVE_IFACE_IFREQ=no,samba_cv_HAVE_IFACE_IFREQ=cross)])
if test x"$samba_cv_HAVE_IFACE_IFREQ" = x"yes"; then
    iface=yes;AC_DEFINE(HAVE_IFACE_IFREQ,1,[Whether iface ifreq is available])
fi
fi

LIBS=$old_LIBS
