dnl # NTVFS Server subsystem

SMB_MODULE_MK(ntvfs_cifs, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_simple, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_print, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_ipc, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_posix, NTVFS, STATIC, ntvfs/config.mk)

SMB_MODULE_MK(ntvfs_nbench, NTVFS, STATIC, ntvfs/config.mk)

SMB_SUBSYSTEM_MK(NTVFS,ntvfs/config.mk)
