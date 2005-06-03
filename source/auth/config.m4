###############################
# start SMB_EXT_LIB_PAM
# check for security/pam_appl.h and -lpam
AC_CHECK_HEADERS(security/pam_appl.h)
AC_CHECK_LIB_EXT(pam, PAM_LIBS, pam_start)
if test x"$ac_cv_header_security_pam_appl_h" = x"yes" -a x"$ac_cv_lib_ext_pam_pam_start" = x"yes";then
	SMB_EXT_LIB_ENABLE(PAM,YES)
fi
SMB_EXT_LIB(PAM, $PAM_LIBS)
# end SMB_EXT_LIB_PAM
###############################
