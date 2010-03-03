######
AC_CHECK_HEADERS(nss.h nss_common.h ns_api.h )

case "$host_os" in
	*linux*)
	    if test x"$MERGED_BUILD" != x"1"; then
		SMB_BUILD_LIBRARY(nss_winbind,
			    [../nsswitch/winbind_nss_linux.o],
			    [LIBWINBIND-CLIENT])
		SMB_MAKE_SETTINGS([nss_winbind_VERSION = 2])
		SMB_MAKE_SETTINGS([nss_winbind_SOVERSION = 2])
	    fi
	;;
	*)
	;;
esac
#####

#####
#All the pam requirement tests are regrouped here
#It is mandatory not to remove them otherwise it will break badly the source4/auth part
AC_CHECK_HEADERS(security/pam_appl.h)
AC_CHECK_LIB_EXT(pam, PAM_LIBS, pam_start)
# This part is need for the compilation
AC_CHECK_HEADERS(security/pam_modules.h pam/pam_modules.h,,,[[
    #if HAVE_SECURITY_PAM_APPL_H
    #include <security/pam_appl.h>
    #endif
    #if HAVE_PAM_PAM_APPL_H
    #include <pam/pam_appl.h>
    #endif
]])

SMB_EXT_LIB(PAM, $PAM_LIBS)

if test x"$ac_cv_header_security_pam_appl_h" = x"yes" -a x"$ac_cv_lib_ext_pam_pam_start" = x"yes";then
	SMB_ENABLE(PAM,YES)
	if test x"$MERGED_BUILD" != x"1"; then
		SMB_BUILD_LIBRARY(pam_winbind,[../nsswitch/pam_winbind.o],
				  [LIBWBCLIENT LIBWINBIND-CLIENT LIBINIPARSER PAM],
				  [-DLOCALEDIR=\\\"${datarootdir}/locale\\\"],
				  [],
				  [../nsswitch/pam_winbind.\$(SHLIBEXT)])
	fi
fi
#####
