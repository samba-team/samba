
dnl test for ipv6 using the gethostbyname2() function. That should be sufficient
dnl for now
AC_CHECK_FUNCS(gethostbyname2, have_ipv6=true, have_ipv6=false)
if $have_ipv6 = true; then
    SMB_MODULE_DEFAULT(socket_ipv6, STATIC)
    AC_DEFINE(HAVE_SOCKET_IPV6,1,[Whether the system has ipv6 support])
fi

dnl don't build ipv6 by default, unless the above test enables it, or
dnl the configure uses --with-static-modules=socket_ipv6
