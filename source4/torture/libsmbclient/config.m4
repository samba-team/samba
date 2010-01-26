###############################
# start SMB_EXT_LIB_LIBSMBCLIENT
# check for libsmbclient.h and -lsmbclient

use_libsmbclient=auto
AC_ARG_ENABLE(libsmbclient,
AS_HELP_STRING([--enable-libsmbclient],[Turn on libsmbclient support (default=auto)]),
    [if test x$enable_libsmbclient = xno; then
        use_libsmbclient=no
    fi])


#if test x$use_libsmbclient = xauto && pkg-config --exists libsmbclient; then
#	SMB_EXT_LIB_FROM_PKGCONFIG(LIBSMBCLIENT, libsmbclient < 0.1,
#							   [use_libsmbclient=yes],
#							   [use_libsmbclient=no])
#fi

SMB_ENABLE(TORTURE_LIBSMBCLIENT,NO)
if test x$use_libsmbclient != xno; then
	AC_CHECK_HEADERS(libsmbclient.h)
	AC_CHECK_LIB_EXT(smbclient, SMBCLIENT_LIBS, smbc_new_context)
	AC_CHECK_LIB_EXT(smbclient, SMBCLIENT_LIBS, smbc_getOptionNoAutoAnonymousLogin)
	AC_CHECK_LIB_EXT(smbclient, SMBCLIENT_LIBS, smbc_setOptionCaseSensitive)
	AC_CHECK_LIB_EXT(smbclient, SMBCLIENT_LIBS, smbc_setOptionUseCCache)
	if test x"$ac_cv_header_libsmbclient_h" = x"yes" -a x"$ac_cv_lib_ext_smbclient_smbc_new_context" = x"yes" -a x"$ac_cv_lib_ext_smbclient_smbc_getOptionNoAutoAnonymousLogin" = x"yes" -a x"$ac_cv_lib_ext_smbclient_smbc_setOptionCaseSensitive" = x"yes" -a x"$ac_cv_lib_ext_smbclient_smbc_setOptionUseCCache" = x"yes"; then
		AC_DEFINE(ENABLE_LIBSMBCLIENT,1,[Whether we have libsmbclient on the host system])
		SMB_ENABLE(SMBCLIENT,YES)
		SMB_ENABLE(TORTURE_LIBSMBCLIENT,YES)
	else
		if test x$use_libsmbclient != xauto; then
			AC_MSG_ERROR([--enable-libsmbclient: libsmbclient not found])
		fi
	fi
	SMB_EXT_LIB(SMBCLIENT, $SMBCLIENT_LIBS)
fi
