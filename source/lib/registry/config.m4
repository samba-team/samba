# Registry backends
                                                                                                                              
if test t$BLDSHARED = ttrue; then
    LIBWINREG_SHARED=bin/libwinregistry.$SHLIBEXT
fi
LIBWINREG=libwinregistry

PKG_CHECK_MODULES(GCONF, gconf-2.0, [ SMB_MODULE_DEFAULT(reg_gconf,STATIC)
				  CFLAGS="$CFLAGS $GCONF_CFLAGS";], [AC_MSG_WARN([GConf not found, not building reg_gconf])])

SMB_MODULE(reg_nt4, REG, STATIC, lib/registry/reg_backend_nt4/reg_backend_nt4.o)
SMB_MODULE(reg_dir, REG, STATIC, lib/registry/reg_backend_dir/reg_backend_dir.o)
SMB_MODULE(reg_rpc, REG, STATIC, lib/registry/reg_backend_rpc/reg_backend_rpc.o)
SMB_MODULE(reg_gconf, REG, NOT, lib/registry/reg_backend_gconf/reg_backend_gconf.o, [], [$GCONF_LIBS])
SMB_SUBSYSTEM(REG,lib/registry/common/reg_interface.o,[lib/registry/common/reg_objects.o lib/registry/common/reg_util.o],lib/registry/common/winregistry_proto.h,[])
AC_OUTPUT(lib/registry/winregistry.pc)
