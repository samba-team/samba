AC_CHECK_HEADERS([ifaddrs.h])

dnl Used when getifaddrs is not available
AC_CHECK_MEMBERS([struct sockaddr.sa_len], 
	 [AC_DEFINE(HAVE_SOCKADDR_SA_LEN, 1, [Whether struct sockaddr has a sa_len member])],
	 [],
	 [#include <sys/socket.h>])

dnl test for getifaddrs and freeifaddrs
AC_CACHE_CHECK([for getifaddrs and freeifaddrs],libreplace_cv_HAVE_GETIFADDRS,[
AC_TRY_COMPILE([
#include <sys/types.h>
#if STDC_HEADERS
#include <stdlib.h>
#include <stddef.h>
#endif
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <netdb.h>],
[
struct ifaddrs *ifp = NULL;
int ret = getifaddrs (&ifp);
freeifaddrs(ifp);
],
libreplace_cv_HAVE_GETIFADDRS=yes,libreplace_cv_HAVE_GETIFADDRS=no)])
if test x"$libreplace_cv_HAVE_GETIFADDRS" = x"yes"; then
    AC_DEFINE(HAVE_GETIFADDRS,1,[Whether the system has getifaddrs])
    AC_DEFINE(HAVE_FREEIFADDRS,1,[Whether the system has freeifaddrs])
	AC_DEFINE(HAVE_STRUCT_IFADDRS,1,[Whether struct ifaddrs is available])
fi

##################
# look for a method of finding the list of network interfaces
#
# This tests need LIBS="$NSL_LIBS $SOCKET_LIBS"
#
old_LIBS=$LIBS
LIBS="$NSL_LIBS $SOCKET_LIBS"
iface=no;
##################
# look for a method of finding the list of network interfaces
iface=no;
AC_CACHE_CHECK([for iface getifaddrs],libreplace_cv_HAVE_IFACE_GETIFADDRS,[
AC_TRY_RUN([
#define NO_CONFIG_H 1
#define HAVE_IFACE_GETIFADDRS 1
#define AUTOCONF_TEST 1
#include "$libreplacedir/replace.c"
#include "$libreplacedir/getifaddrs.c"],
           libreplace_cv_HAVE_IFACE_GETIFADDRS=yes,libreplace_cv_HAVE_IFACE_GETIFADDRS=no,libreplace_cv_HAVE_IFACE_GETIFADDRS=cross)])
if test x"$libreplace_cv_HAVE_IFACE_GETIFADDRS" = x"yes"; then
    iface=yes;AC_DEFINE(HAVE_IFACE_GETIFADDRS,1,[Whether iface getifaddrs is available])
else
	LIBREPLACEOBJ="${LIBREPLACEOBJ} getifaddrs.o"
fi


if test $iface = no; then
AC_CACHE_CHECK([for iface AIX],libreplace_cv_HAVE_IFACE_AIX,[
AC_TRY_RUN([
#define NO_CONFIG_H 1
#define HAVE_IFACE_AIX 1
#define AUTOCONF_TEST 1
#undef _XOPEN_SOURCE_EXTENDED
#include "$libreplacedir/getifaddrs.c"],
           libreplace_cv_HAVE_IFACE_AIX=yes,libreplace_cv_HAVE_IFACE_AIX=no,libreplace_cv_HAVE_IFACE_AIX=cross)])
if test x"$libreplace_cv_HAVE_IFACE_AIX" = x"yes"; then
    iface=yes;AC_DEFINE(HAVE_IFACE_AIX,1,[Whether iface AIX is available])
fi
fi


if test $iface = no; then
AC_CACHE_CHECK([for iface ifconf],libreplace_cv_HAVE_IFACE_IFCONF,[
AC_TRY_RUN([
#define NO_CONFIG_H 1
#define HAVE_IFACE_IFCONF 1
#define AUTOCONF_TEST 1
#include "$libreplacedir/getifaddrs.c"],
           libreplace_cv_HAVE_IFACE_IFCONF=yes,libreplace_cv_HAVE_IFACE_IFCONF=no,libreplace_cv_HAVE_IFACE_IFCONF=cross)])
if test x"$libreplace_cv_HAVE_IFACE_IFCONF" = x"yes"; then
    iface=yes;AC_DEFINE(HAVE_IFACE_IFCONF,1,[Whether iface ifconf is available])
fi
fi

if test $iface = no; then
AC_CACHE_CHECK([for iface ifreq],libreplace_cv_HAVE_IFACE_IFREQ,[
AC_TRY_RUN([
#define NO_CONFIG_H 1
#define HAVE_IFACE_IFREQ 1
#define AUTOCONF_TEST 1
#include "$libreplacedir/getifaddrs.c"],
           libreplace_cv_HAVE_IFACE_IFREQ=yes,libreplace_cv_HAVE_IFACE_IFREQ=no,libreplace_cv_HAVE_IFACE_IFREQ=cross)])
if test x"$libreplace_cv_HAVE_IFACE_IFREQ" = x"yes"; then
    iface=yes;AC_DEFINE(HAVE_IFACE_IFREQ,1,[Whether iface ifreq is available])
fi
fi

LIBS=$old_LIBS
