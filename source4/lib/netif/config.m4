AC_CHECK_HEADERS(arpa/inet.h net/if.h netdb.h netinet/in.h sys/time.h)
AC_CHECK_HEADERS(netinet/ip.h netinet/tcp.h netinet/in_systm.h netinet/in_ip.h)

##################
# look for a method of finding the list of network interfaces
iface=no;
AC_CACHE_CHECK([for iface AIX],samba_cv_HAVE_IFACE_AIX,[
AC_TRY_RUN([
#define HAVE_IFACE_AIX 1
#define AUTOCONF_TEST 1
#include "confdefs.h"
#include "${srcdir-.}/lib/netif/netif.c"],
           samba_cv_HAVE_IFACE_AIX=yes,samba_cv_HAVE_IFACE_AIX=no,samba_cv_HAVE_IFACE_AIX=cross)])
if test x"$samba_cv_HAVE_IFACE_AIX" = x"yes"; then
    iface=yes;AC_DEFINE(HAVE_IFACE_AIX,1,[Whether iface AIX is available])
fi

if test $iface = no; then
AC_CACHE_CHECK([for iface ifconf],samba_cv_HAVE_IFACE_IFCONF,[
AC_TRY_RUN([
#define HAVE_IFACE_IFCONF 1
#define AUTOCONF_TEST 1
#include "confdefs.h"
#include "${srcdir-.}/lib/netif/netif.c"],
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
#include "confdefs.h"
#include "${srcdir-.}/lib/netif/netif.c"],
           samba_cv_HAVE_IFACE_IFREQ=yes,samba_cv_HAVE_IFACE_IFREQ=no,samba_cv_HAVE_IFACE_IFREQ=cross)])
if test x"$samba_cv_HAVE_IFACE_IFREQ" = x"yes"; then
    iface=yes;AC_DEFINE(HAVE_IFACE_IFREQ,1,[Whether iface ifreq is available])
fi
fi
