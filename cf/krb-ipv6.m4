dnl $Id$
dnl
AC_DEFUN(AC_KRB_IPV6, [
AC_MSG_CHECKING(for IPv6)
foo=no
AC_EGREP_HEADER(sockaddr_in6, netinet/in.h,
AC_DEFINE(HAVE_STRUCT_SOCKADDR_IN6) foo=yes)
AC_EGREP_HEADER(sockaddr_in6, netinet/in6.h,
AC_DEFINE(HAVE_STRUCT_SOCKADDR_IN6) foo=yes)
AC_MSG_RESULT($foo)
])
