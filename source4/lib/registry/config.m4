# Registry backends
                                                                                                                              
if test t$BLDSHARED = ttrue; then
    LIBWINREG_SHARED=bin/libwinregistry.$SHLIBEXT
fi
LIBWINREG=libwinregistry

AC_CONFIG_FILES(lib/registry/winregistry.pc)

SMB_MODULE_DEFAULT(registry_gconf, NOT)

SMB_EXT_LIB_FROM_PKGCONFIG(gconf, gconf-2.0)

if test t$SMB_EXT_LIB_ENABLE_gconf = tYES; then
	SMB_MODULE_DEFAULT(registry_gconf, STATIC)
fi

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libwinregistry, YES)
fi
