# NTVFS Server subsystem

################################################
# Start MODULE ntvfs_cifs
[MODULE::ntvfs_cifs]
INIT_OBJ_FILES = \
		ntvfs/cifs/vfs_cifs.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI
# End MODULE ntvfs_cifs
################################################

################################################
# Start MODULE ntvfs_simple
[MODULE::ntvfs_simple]
INIT_OBJ_FILES = \
		ntvfs/simple/vfs_simple.o
ADD_OBJ_FILES = \
		ntvfs/simple/svfs_util.o
# End MODULE ntvfs_cifs
################################################

################################################
# Start MODULE ntvfs_print
[MODULE::ntvfs_print]
INIT_OBJ_FILES = \
		ntvfs/print/vfs_print.o
# End MODULE ntvfs_print
################################################

################################################
# Start MODULE ntvfs_ipc
[MODULE::ntvfs_ipc]
INIT_OBJ_FILES = \
		ntvfs/ipc/vfs_ipc.o \
		ntvfs/ipc/ipc_rap.o \
		ntvfs/ipc/rap_server.o
# End MODULE ntvfs_ipc
################################################



################################################
# Start MODULE ntvfs_nbench
[MODULE::ntvfs_nbench]
INIT_OBJ_FILES = \
		ntvfs/nbench/vfs_nbench.o
# End MODULE ntvfs_nbench
################################################

################################################
# Start SUBSYSTEM NTVFS
[SUBSYSTEM::NTVFS]
INIT_OBJ_FILES = \
		ntvfs/ntvfs_base.o
ADD_OBJ_FILES = \
		ntvfs/ntvfs_generic.o \
		ntvfs/ntvfs_interface.o \
		ntvfs/ntvfs_util.o
#
# End SUBSYSTEM NTVFS
################################################
