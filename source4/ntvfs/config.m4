dnl # NTVFS Server subsystem

SMB_MODULE(ntvfs_cifs, STATIC, \$(NTVFS_CIFS_OBJ), "bin/cifs.$SHLIBEXT$", NTVFS)
SMB_MODULE(ntvfs_simple, STATIC, \$(NTVFS_SIMPLE_OBJ), "bin/ntvfs_simple.$SHLIBEXT$", NTVFS)
SMB_MODULE(ntvfs_print, STATIC, \$(NTVFS_PRINT_OBJ), "bin/ntvfs_print.$SHLIBEXT$", NTVFS)
SMB_MODULE(ntvfs_ipc, STATIC, \$(NTVFS_IPC_OBJ), "bin/ntvfs_ipc.$SHLIBEXT$", NTVFS)
SMB_MODULE(ntvfs_posix, NOT, \$(NTVFS_POSIX_OBJ), "bin/ntvfs_posix.$SHLIBEXT$", NTVFS)

SMB_SUBSYSTEM(NTVFS,ntvfs/ntvfs_base.o)
