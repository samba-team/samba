# Registry backends
                                                                                                                              
if test t$BLDSHARED = ttrue; then
    LIBWINREG_SHARED=bin/libwinregistry.$SHLIBEXT
fi
LIBWINREG=libwinregistry

PKG_CHECK_MODULES(GCONF, gconf-2.0, [ SMB_MODULE_DEFAULT(registry_gconf,STATIC)
				CFLAGS="$CFLAGS $GCONF_CFLAGS";], [AC_MSG_WARN([GConf not found, not building registry_gconf])])
AC_CONFIG_FILES(lib/registry/winregistry.pc)

SMB_BINARY_ENABLE(gregedit,NO)

#disable grpedit for now
PKG_CHECK_MODULES(GTK, glib-2.0 gtk+-2.0, [ SMB_BINARY_ENABLE(gregedit,NO)
				CFLAGS="$CFLAGS $GTK_CFLAGS"; ], [ AC_MSG_WARN([Will be unable to build gregedit])])

SMB_MODULE(registry_nt4, REGISTRY, STATIC, lib/registry/reg_backend_nt4/reg_backend_nt4.o)
SMB_MODULE(registry_w95, REGISTRY, STATIC, lib/registry/reg_backend_w95/reg_backend_w95.o)
SMB_MODULE(registry_dir, REGISTRY, STATIC, lib/registry/reg_backend_dir/reg_backend_dir.o)
SMB_MODULE(registry_rpc, REGISTRY, STATIC, lib/registry/reg_backend_rpc/reg_backend_rpc.o,[],[],[LIBSMB])
SMB_MODULE(registry_gconf, REGISTRY, NOT, lib/registry/reg_backend_gconf/reg_backend_gconf.o)
SMB_MODULE(registry_ldb, REGISTRY, NOT, lib/registry/reg_backend_ldb/reg_backend_ldb.o,[],[],[LIBLDB])
SMB_SUBSYSTEM(REGISTRY,lib/registry/common/reg_interface.o,
	[lib/registry/common/reg_objects.o lib/registry/common/reg_util.o],
	[],
	[LIBBASIC])

SMB_BINARY(regdiff, [REG], [BIN], lib/registry/tools/regdiff.o,[],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])
SMB_BINARY(regpatch, [REG], [BIN], lib/registry/tools/regpatch.o,[],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])
SMB_BINARY(regshell, [REG], [BIN], lib/registry/tools/regshell.o,[],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])
SMB_BINARY(regtree, [REG], [BIN], lib/registry/tools/regtree.o,[],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])
SMB_BINARY(gregedit, [REG], [BIN], lib/registry/tools/gregedit.o,[],[CONFIG LIBBASIC LIBCMDLINE REGISTRY])
