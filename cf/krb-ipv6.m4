dnl $Id$
dnl
dnl test for IPv6
dnl
AC_DEFUN(AC_KRB_IPV6, [
AC_CACHE_CHECK(for IPv6,ac_cv_lib_ipv6,
AC_TRY_COMPILE([
#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
#include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
#include <netinet/in.h>
#endif
#ifdef HAVE_NETINET_IN6_H
#include <netinet/in6.h>
#endif
],
[
#if defined(IN6ADDR_ANY_INIT)
struct in6_addr any = IN6ADDR_ANY_INIT;
#elif defined(IPV6ADDR_ANY_INIT)
struct in6_addr any = IPV6ADDR_ANY_INIT;
#else
#error no any?
#endif
 struct sockaddr_in6 sin6;
 int s;

 s = socket(AF_INET6, SOCK_DGRAM, 0);

 sin6.sin6_family = AF_INET6;
 sin6.sin6_port = htons(17);
 sin6.sin6_addr = any;
 bind(s, (struct sockaddr *)&sin6, sizeof(sin6));
],
ac_cv_lib_ipv6=yes,
ac_cv_lib_ipv6=no))
if test "$ac_cv_lib_ipv6" = yes; then
  AC_DEFINE(HAVE_IPV6)
fi
])
