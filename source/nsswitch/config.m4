AC_CHECK_HEADERS(nss.h nss_common.h ns_api.h )

case "$host_os" in
	*linux*)
		SMB_LIBRARY(nss_winbind,
			    [Linux Name service switch library using winbind],
			    [nsswitch/winbind_nss_linux.o],
			    [LIBWINBIND-CLIENT],
			    [2],[2])
	;;
	*)
	;;
esac

