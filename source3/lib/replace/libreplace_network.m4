AC_DEFUN_ONCE(AC_LIBREPLACE_NETWORK_CHECKS,
[
echo "LIBREPLACE_NETWORK_CHECKS: START"

AC_CHECK_HEADERS(sys/socket.h netinet/in.h netdb.h arpa/inet.h)
AC_CHECK_HEADERS(netinet/ip.h netinet/tcp.h netinet/in_systm.h netinet/in_ip.h)

dnl we need to check that net/if.h really can be used, to cope with hpux
dnl where including it always fails
AC_CACHE_CHECK([for usable net/if.h],libreplace_cv_USABLE_NET_IF_H,[
	AC_COMPILE_IFELSE([AC_LANG_SOURCE([
		AC_INCLUDES_DEFAULT
		#if HAVE_SYS_SOCKET_H
		# include <sys/socket.h>
		#endif
		#include <net/if.h>
		int main(void) {return 0;}])],
		[libreplace_cv_USABLE_NET_IF_H=yes],
		[libreplace_cv_USABLE_NET_IF_H=no]
	)
])
if test x"$libreplace_cv_USABLE_NET_IF_H" = x"yes";then
	AC_DEFINE(HAVE_NET_IF_H, 1, usability of net/if.h)
fi

AC_HAVE_TYPE([socklen_t],[#include <sys/socket.h>])
AC_HAVE_TYPE([sa_family_t],[#include <sys/socket.h>])
AC_HAVE_TYPE([struct addrinfo], [#include <netdb.h>])
AC_HAVE_TYPE([struct sockaddr], [#include <sys/socket.h>])
AC_HAVE_TYPE([struct sockaddr_storage], [
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
])
AC_HAVE_TYPE([struct sockaddr_in6], [
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
])

if test x"$ac_cv_type_struct_sockaddr_storage" = x"yes"; then
AC_CHECK_MEMBER(struct sockaddr_storage.ss_family,
                AC_DEFINE(HAVE_SS_FAMILY, 1, [Defined if struct sockaddr_storage has ss_family field]),,
                [
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
		])

if test x"$ac_cv_member_struct_sockaddr_storage_ss_family" != x"yes"; then
AC_CHECK_MEMBER(struct sockaddr_storage.__ss_family,
                AC_DEFINE(HAVE___SS_FAMILY, 1, [Defined if struct sockaddr_storage has __ss_family field]),,
                [
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
		])
fi
fi

m4_include(socket.m4)
m4_include(inet_ntop.m4)
m4_include(inet_pton.m4)
m4_include(inet_aton.m4)
m4_include(inet_ntoa.m4)
m4_include(getaddrinfo.m4)
m4_include(getifaddrs.m4)
m4_include(socketpair.m4)

echo "LIBREPLACE_NETWORK_CHECKS: END"
]) dnl end AC_LIBREPLACE_NETWORK_CHECKS
