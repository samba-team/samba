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

SMB_MODULE(registry_nt4, REGISTRY, STATIC, lib/registry/reg_backend_nt4/reg_backend_nt4.o)
SMB_MODULE(registry_w95, REGISTRY, STATIC, lib/registry/reg_backend_w95/reg_backend_w95.o)
SMB_MODULE(registry_dir, REGISTRY, STATIC, lib/registry/reg_backend_dir/reg_backend_dir.o)
SMB_MODULE(registry_rpc, REGISTRY, STATIC, lib/registry/reg_backend_rpc/reg_backend_rpc.o,[],[],[LIBSMB])
SMB_MODULE(registry_gconf, REGISTRY, STATIC, lib/registry/reg_backend_gconf/reg_backend_gconf.o, [], [gconf])
SMB_MODULE(registry_ldb, REGISTRY, NOT, lib/registry/reg_backend_ldb/reg_backend_ldb.o,[],[],[LIBLDB])
SMB_SUBSYSTEM(REGISTRY,lib/registry/common/reg_interface.o,
	[lib/registry/common/reg_objects.o lib/registry/common/reg_util.o],
	[],
	[LIBBASIC])

SMB_BINARY(regdiff, [REG], [BIN], lib/registry/tools/regdiff.o,[],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])
SMB_BINARY(regpatch, [REG], [BIN], lib/registry/tools/regpatch.o,[],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])
SMB_BINARY(regshell, [REG], [BIN], lib/registry/tools/regshell.o,[],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])
SMB_BINARY(regtree, [REG], [BIN], lib/registry/tools/regtree.o,[],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])
SMB_BINARY(gregedit, [REG], [BIN], lib/registry/tools/gregedit.o,[gtk],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])

if test x"$experimental" = x"yes"; then
	SMB_LIBRARY_ENABLE(libwinregistry, YES)
fi

SMB_LIBRARY(libwinregistry, 0, 0, 1, , , REGISTRY) 
