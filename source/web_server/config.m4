AC_CHECK_HEADERS(setjmp.h)

###############################
# start SMB_EXT_LIB_GNUTLS
# check for gnutls/gnutls.h and -lgnutls
AC_CHECK_HEADERS(gnutls/gnutls.h)
AC_CHECK_LIB_EXT(gnutls, GNUTLS_LIBS, gnutls_global_init)
if test x"$ac_cv_header_gnutls_gnutls_h" = x"yes" -a x"$ac_cv_lib_ext_gnutls_gnutls_global_init" = x"yes";then
	SMB_EXT_LIB_ENABLE(GNUTLS,YES)
fi
SMB_EXT_LIB(GNUTLS, $GNUTLS_LIBS)
# end SMB_EXT_LIB_GNUTLS
###############################
