# Registry backends
SMB_MODULE_DEFAULT(registry_gconf, NOT)

SMB_EXT_LIB_FROM_PKGCONFIG(gconf, gconf-2.0)

AC_ARG_ENABLE(reg-gconf,
[   --enable-reg-gconf     Enable support for GConf registry backend],
[
	if test t$enable = tyes && test t$SMB_EXT_LIB_ENABLE_gconf = tYES; then
		SMB_MODULE_DEFAULT(registry_gconf, STATIC)
	fi
])
