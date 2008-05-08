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

dnl The following test is roughl taken from the cvs sources.
dnl
dnl If we can't find connect, try looking in -lsocket, -lnsl, and -linet.
dnl The Irix 5 libc.so has connect and gethostbyname, but Irix 5 also has
dnl libsocket.so which has a bad implementation of gethostbyname (it
dnl only looks in /etc/hosts), so we only look for -lsocket if we need
dnl it.
AC_CHECK_FUNCS(connect)
if test x"$ac_cv_func_connect" = x"no"; then
	AC_CHECK_LIB_EXT(nsl_s, LIBREPLACE_NETWORK_LIBS, connect)
	AC_CHECK_LIB_EXT(nsl, LIBREPLACE_NETWORK_LIBS, connect)
	AC_CHECK_LIB_EXT(socket, LIBREPLACE_NETWORK_LIBS, connect)
	AC_CHECK_LIB_EXT(inet, LIBREPLACE_NETWORK_LIBS, connect)
	dnl We can't just call AC_CHECK_FUNCS(connect) here,
	dnl because the value has been cached.
	if test x"$ac_cv_lib_ext_nsl_s_connect" = x"yes" ||
		test x"$ac_cv_lib_ext_nsl_connect" = x"yes" ||
		test x"$ac_cv_lib_ext_socket_connect" = x"yes" ||
		test x"$ac_cv_lib_ext_inet_connect" = x"yes"
	then
		AC_DEFINE(HAVE_CONNECT,1,[Whether the system has connect()])
	fi
fi

AC_CHECK_FUNCS(gethostbyname)
if test x"$ac_cv_func_gethostbyname" = x"no"; then
	AC_CHECK_LIB_EXT(nsl_s, LIBREPLACE_NETWORK_LIBS, gethostbyname)
	AC_CHECK_LIB_EXT(nsl, LIBREPLACE_NETWORK_LIBS, gethostbyname)
	AC_CHECK_LIB_EXT(socket, LIBREPLACE_NETWORK_LIBS, gethostbyname)
	dnl We can't just call AC_CHECK_FUNCS(gethostbyname) here,
	dnl because the value has been cached.
	if test x"$ac_cv_lib_ext_nsl_s_gethostbyname" = x"yes" ||
		test x"$ac_cv_lib_ext_nsl_gethostbyname" = x"yes" ||
		test x"$ac_cv_lib_ext_socket_gethostbyname" = x"yes"
	then
		AC_DEFINE(HAVE_GETHOSTBYNAME,1,
			  [Whether the system has gethostbyname()])
	fi
fi

AC_CHECK_FUNCS(inet_ntoa,[],[LIBREPLACEOBJ="${LIBREPLACEOBJ} inet_ntoa.o"])

AC_CACHE_CHECK([for broken inet_ntoa],libreplace_cv_REPLACE_INET_NTOA,[
AC_TRY_RUN([
#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <netinet/in.h>
#ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif
main() { struct in_addr ip; ip.s_addr = 0x12345678;
if (strcmp(inet_ntoa(ip),"18.52.86.120") &&
    strcmp(inet_ntoa(ip),"120.86.52.18")) { exit(0); }
exit(1);}],
           libreplace_cv_REPLACE_INET_NTOA=yes,libreplace_cv_REPLACE_INET_NTOA=no,libreplace_cv_REPLACE_INET_NTOA=cross)])
if test x"$libreplace_cv_REPLACE_INET_NTOA" = x"yes"; then
    AC_DEFINE(REPLACE_INET_NTOA,1,[Whether inet_ntoa should be replaced])
fi

m4_include(inet_ntop.m4)
m4_include(inet_pton.m4)
m4_include(inet_aton.m4)
m4_include(getaddrinfo.m4)
m4_include(getifaddrs.m4)
m4_include(socketpair.m4)

echo "LIBREPLACE_NETWORK_CHECKS: END"
]) dnl end AC_LIBREPLACE_NETWORK_CHECKS
