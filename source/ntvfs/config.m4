dnl # NTVFS Server subsystem

SMB_MODULE(ntvfs_cifs, NTVFS, STATIC, \$(NTVFS_CIFS_OBJ), "bin/cifs.$SHLIBEXT$")
SMB_MODULE(ntvfs_simple, NTVFS, STATIC, \$(NTVFS_SIMPLE_OBJ), "bin/ntvfs_simple.$SHLIBEXT$")
SMB_MODULE(ntvfs_print, NTVFS, STATIC, \$(NTVFS_PRINT_OBJ), "bin/ntvfs_print.$SHLIBEXT$")
SMB_MODULE(ntvfs_ipc, NTVFS, STATIC, \$(NTVFS_IPC_OBJ), "bin/ntvfs_ipc.$SHLIBEXT$")
SMB_MODULE(ntvfs_posix, NTVFS, NOT, \$(NTVFS_POSIX_OBJ), "bin/ntvfs_posix.$SHLIBEXT$")

SMB_SUBSYSTEM(NTVFS,ntvfs/ntvfs_base.o)
