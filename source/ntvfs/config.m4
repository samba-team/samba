dnl # NTVFS Server subsystem

SMB_MODULE(ntvfs_cifs, NTVFS, STATIC, [ntvfs/cifs/vfs_cifs.o])

SMB_MODULE(ntvfs_simple, NTVFS, STATIC, 
		[ntvfs/simple/vfs_simple.o ntvfs/simple/svfs_util.o], 
		ntvfs/simple/svfs_private.h)

SMB_MODULE(ntvfs_print, NTVFS, STATIC, [ntvfs/print/vfs_print.o])

SMB_MODULE(ntvfs_ipc, NTVFS, STATIC, [ntvfs/ipc/vfs_ipc.o])

SMB_MODULE(ntvfs_posix, NTVFS, NOT, [ntvfs/posix/vfs_posix.o])

SMB_SUBSYSTEM(NTVFS,ntvfs/ntvfs_base.o,
		[ntvfs/ntvfs_generic.o ntvfs/ntvfs_util.o],
		ntvfs_public_proto.h)
