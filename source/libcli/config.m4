dnl # LIBCLI subsystem

LIBCLI_RAW_LIBS=
if test x"$with_ads_support" = x"yes"; then
	LIBCLI_RAW_LIBS="KRB5"
fi

SMB_SUBSYSTEM(LIBCLI_RAW_KRB5, [], [${LIBCLI_RAW_LIBS}])
