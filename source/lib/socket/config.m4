
SMB_MODULE_MK(socket_ipv4,SOCKET,STATIC,lib/socket/config.mk)
SMB_MODULE_MK(socket_unix,SOCKET,STATIC,lib/socket/config.mk)

AC_CHECK_FUNCS(gethostbyname2, have_ipv6=true, have_ipv6=false)
if $have_ipv6 = true; then
    AC_DEFINE(HAVE_SOCKET_IPV6,1,[Whether the system has ipv6 support])
    SMB_MODULE_MK(socket_ipv6,SOCKET,STATIC,lib/socket/config.mk)
fi

SMB_SUBSYSTEM_MK(SOCKET,lib/socket/config.mk)
