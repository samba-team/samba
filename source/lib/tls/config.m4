###############################
# start SMB_EXT_LIB_GNUTLS
# check for gnutls/gnutls.h and -lgnutls
#
# Should eventually change to simply:
# SMB_EXT_LIB_FROM_PKGCONFIG(GNUTLS, gnutls)
AC_CHECK_HEADERS(gnutls/gnutls.h)
AC_CHECK_LIB_EXT(gnutls, GNUTLS_LIBS, gnutls_global_init)
if test x"$ac_cv_header_gnutls_gnutls_h" = x"yes" -a x"$ac_cv_lib_ext_gnutls_gnutls_global_init" = x"yes";then
	SMB_ENABLE(GNUTLS,YES)
	AC_CHECK_DECL(gnutls_x509_crt_set_subject_key_id,  
	              [AC_DEFINE(HAVE_GNUTLS_X509_CRT_SET_SUBJECT_KEY_ID,1,gnutls subject_key)], [], [
#include <gnutls/gnutls.h>
#include <gnutls/x509.h>
])
fi
SMB_EXT_LIB(GNUTLS, $GNUTLS_LIBS)
# end SMB_EXT_LIB_GNUTLS
###############################
