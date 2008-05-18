AC_CHECK_FUNCS(writev)
AC_CHECK_FUNCS(readv)

############################################
# check for unix domain sockets
# done by AC_LIBREPLACE_NETWORK_CHECKS
SMB_ENABLE(socket_unix, NO)
if test x"$libreplace_cv_HAVE_UNIXSOCKET" = x"yes"; then
	SMB_ENABLE(socket_unix, YES)
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




