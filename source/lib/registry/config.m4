# Registry backends
                                                                                                                              
if test t$BLDSHARED = ttrue; then
    LIBWINREG_SHARED=bin/libwinregistry.$SHLIBEXT
fi
LIBWINREG=libwinregistry

AC_CONFIG_FILES(lib/registry/winregistry.pc)

SMB_BINARY_ENABLE(gregedit, NO)
SMB_MODULE_DEFAULT(registry_gconf, NOT)

SMB_EXT_LIB_FROM_PKGCONFIG(gconf, gconf-2.0)

if test t$SMB_EXT_LIB_ENABLE_gconf = tYES; then
	SMB_MODULE_DEFAULT(registry_gconf, STATIC)
fi

SMB_EXT_LIB_FROM_PKGCONFIG(gtk, [glib-2.0 gtk+-2.0])

if test t$SMB_EXT_LIB_ENABLE_gtk = tYES; then
	SMB_BINARY_ENABLE(gregedit, YES)
fi

SMB_MODULE_MK(registry_nt4, REGISTRY, STATIC, lib/registry/config.mk)
SMB_MODULE_MK(registry_w95, REGISTRY, STATIC, lib/registry/config.mk)
SMB_MODULE_MK(registry_dir, REGISTRY, STATIC, lib/registry/config.mk)
SMB_MODULE_MK(registry_rpc, REGISTRY, STATIC, lib/registry/config.mk)
SMB_MODULE_MK(registry_gconf, REGISTRY, STATIC, lib/registry/config.mk)
SMB_MODULE_MK(registry_ldb, REGISTRY, STATIC, lib/registry/config.mk)

SMB_SUBSYSTEM_MK(REGISTRY,lib/registry/config.mk)

SMB_BINARY_MK(regdiff, lib/registry/config.mk)
SMB_BINARY_MK(regpatch, lib/registry/config.mk)
SMB_BINARY_MK(regshell, lib/registry/config.mk)
SMB_BINARY_MK(regtree, lib/registry/config.mk)
SMB_BINARY_MK(gregedit, lib/registry/config.mk)

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libwinregistry, YES)
fi

SMB_LIBRARY_MK(libwinregistry, lib/registry/config.mk) 
