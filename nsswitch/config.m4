AC_CHECK_HEADERS(nss.h nss_common.h ns_api.h )

case "$host_os" in
	*linux*)
	    if test x"$MERGED_BUILD" != x"1"; then
		SMB_BUILD_LIBRARY(nss_winbind,
			    [../nsswitch/winbind_nss_linux.o],
			    [LIBWINBIND-CLIENT])
	    fi
	;;
	*)
	;;
esac
