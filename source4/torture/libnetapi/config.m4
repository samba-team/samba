###############################
# start SMB_EXT_LIB_NETAPI
# check for netapi.h and -lnetapi

use_netapi=auto
AC_ARG_ENABLE(netapi,
AS_HELP_STRING([--enable-netapi],[Turn on netapi support (default=auto)]),
    [if test x$enable_netapi = xno; then
        use_netapi=no
    fi])


#if test x$use_netapi = xauto && pkg-config --exists netapi; then
#	SMB_EXT_LIB_FROM_PKGCONFIG(NETAPI, netapi < 0.1,
#							   [use_netapi=yes],
#							   [use_netapi=no])
#fi

SMB_ENABLE(TORTURE_LIBNETAPI,NO)
if test x$use_netapi != xno; then
	AC_CHECK_HEADERS(netapi.h)
	AC_CHECK_LIB_EXT(netapi, NETAPI_LIBS, libnetapi_init)
	if test x"$ac_cv_header_netapi_h" = x"yes" -a x"$ac_cv_lib_ext_netapi_libnetapi_init" = x"yes";then
		SMB_ENABLE(NETAPI,YES)
		SMB_ENABLE(TORTURE_LIBNETAPI,YES)
	else
		if test x$use_netapi != xauto; then
			AC_MSG_ERROR([--enable-netapi: libnetapi not found])
		fi
	fi
	SMB_EXT_LIB(NETAPI, $NETAPI_LIBS)
fi
