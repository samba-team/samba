# Registry backends
SMB_ENABLE(registry_gconf, NO)

SMB_EXT_LIB_FROM_PKGCONFIG(gconf, gconf-2.0)

AC_ARG_ENABLE(reg-gconf,
[   --enable-reg-gconf     Enable support for GConf registry backend],
[
	if test t$enable = tyes; then
		SMB_ENABLE(registry_gconf, $SMB_ENABLE_gconf)
	fi
])
