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

SOCKET_LIBS="${LIBREPLACE_NETWORK_LIBS}"
NSL_LIBS=""
