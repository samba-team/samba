###############################
# start SMB_EXT_LIB_NETAPI
# check for netapi.h and -lnetapi

use_netapi=auto
AC_ARG_ENABLE(netapi,
AS_HELP_STRING([--enable-netapi],[Turn on netapi support (default=yes)]),
    [if test x$enable_netapi = xno; then
        use_netapi=no
    fi])


#if test x$use_netapi = xauto && pkg-config --exists netapi; then
#	SMB_EXT_LIB_FROM_PKGCONFIG(NETAPI, netapi < 0.1,
#							   [use_netapi=yes],
#							   [use_netapi=no])
#fi

if test x$use_netapi = xauto; then
	AC_CHECK_HEADERS(netapi.h)
	AC_CHECK_LIB_EXT(netapi, NETAPI_LIBS, libnetapi_init)
	if test x"$ac_cv_header_netapi_h" = x"yes" -a x"$ac_cv_lib_ext_netapi_libnetapi_init" = x"yes";then
		SMB_ENABLE(NETAPI,YES)
	else
		SMB_ENABLE(TORTURE_LIBNETAPI,NO)
	fi
	SMB_EXT_LIB(NETAPI, $NETAPI_LIBS)
fi
