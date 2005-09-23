AC_CHECK_HEADERS(sys/socket.h sys/sockio.h sys/un.h)

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
    case "$LIBS $SOCKET_LIBS" in
    *-lnsl*) ;;
    *) AC_CHECK_LIB_EXT(nsl_s, SOCKET_LIBS, printf) ;;
    esac
    case "$LIBS $SOCKET_LIBS" in
    *-lnsl*) ;;
    *) AC_CHECK_LIB_EXT(nsl, SOCKET_LIBS, printf) ;;
    esac
    case "$LIBS $SOCKET_LIBS" in
    *-lsocket*) ;;
    *) AC_CHECK_LIB_EXT(socket,  SOCKET_LIBS, connect) ;;
    esac
    case "$LIBS $SOCKET_LIBS" in
    *-linet*) ;;
    *) AC_CHECK_LIB_EXT(inet, SOCKET_LIBS, connect) ;;
    esac
    dnl We can't just call AC_CHECK_FUNCS(connect) here, because the value
    dnl has been cached.
    if test x"$ac_cv_lib_ext_socket_connect" = x"yes" ||
       test x"$ac_cv_lib_ext_inet_connect" = x"yes"; then
        # ac_cv_func_connect=yes
        # don't!  it would cause AC_CHECK_FUNC to succeed next time configure is run
        AC_DEFINE(HAVE_CONNECT,1,[Whether the system has connect()])
    fi
fi
SMB_EXT_LIB(SOCKET,[${SOCKET_LIBS}],[${SOCKET_CFLAGS}],[${SOCKET_CPPFLAGS}],[${SOCKET_LDFLAGS}])

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
SMB_MODULE_DEFAULT(socket_unix, NOT)
if test x"$samba_cv_unixsocket" = x"yes"; then
    SMB_MODULE_DEFAULT(socket_unix, STATIC)
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
SMB_MODULE_DEFAULT(socket_ipv6, NOT)
if $have_ipv6 = true; then
    SMB_MODULE_DEFAULT(socket_ipv6, STATIC)
    AC_DEFINE(HAVE_SOCKET_IPV6,1,[Whether the system has ipv6 support])
fi
dnl don't build ipv6 by default, unless the above test enables it, or
dnl the configure uses --with-static-modules=socket_ipv6
