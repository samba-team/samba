default_static_modules="$default_static_modules ntvfs_ipc ntvfs_simple ntvfs_print ntvfs_cifs"

SMB_MODULE(ntvfs_cifs, \$(NTVFS_CIFS_OBJ), "bin/cifs.$SHLIBEXT$", NTVFS)
SMB_MODULE(ntvfs_simple, \$(NTVFS_SIMPLE_OBJ), "bin/ntvfs_simple.$SHLIBEXT$", NTVFS)
SMB_MODULE(ntvfs_print, \$(NTVFS_PRINT_OBJ), "bin/ntvfs_print.$SHLIBEXT$", NTVFS)
SMB_MODULE(ntvfs_ipc, \$(NTVFS_IPC_OBJ), "bin/ntvfs_ipc.$SHLIBEXT$", NTVFS)
SMB_MODULE(ntvfs_posix, \$(NTVFS_POSIX_OBJ), "bin/ntvfs_posix.$SHLIBEXT$", NTVFS)

# Tank FS
SMB_MODULE(ntvfs_csm, \$(NTVFS_CSM_OBJ), "bin/ntvfs_csm.$SHLIBEXT$", NTVFS)
STFS_ENABLED="#"
if test "$MODULE_ntvfs_csm"; then
	SMBD_EXTRA_LIBS="$SMBD_EXTRA_LIBS \$\(STFS_LIBS\)"
	STFS_ENABLED=
fi
AC_SUBST(STFS_ENABLED)

SMB_SUBSYSTEM(NTVFS,ntvfs/ntvfs_base.o)
