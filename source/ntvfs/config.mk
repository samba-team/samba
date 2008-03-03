# NTVFS Server subsystem
mkinclude posix/config.mk
mkinclude common/config.mk
mkinclude unixuid/config.mk
mkinclude sysdep/config.mk

################################################
# Start MODULE ntvfs_cifs
[MODULE::ntvfs_cifs]
INIT_FUNCTION = ntvfs_cifs_init 
SUBSYSTEM = ntvfs
PRIVATE_DEPENDENCIES = \
		LIBCLI_SMB LIBCLI_RAW
# End MODULE ntvfs_cifs
################################################

ntvfs_cifs_OBJ_FILES = ntvfs/cifs/vfs_cifs.o

################################################
# Start MODULE ntvfs_simple
[MODULE::ntvfs_simple]
INIT_FUNCTION = ntvfs_simple_init 
SUBSYSTEM = ntvfs 
PRIVATE_PROTO_HEADER = simple/proto.h
# End MODULE ntvfs_simple
################################################

ntvfs_simple_OBJ_FILES = $(addprefix ntvfs/simple/, vfs_simple.o svfs_util.o)

################################################
# Start MODULE ntvfs_cifsposix
[MODULE::ntvfs_cifsposix]
#ENABLE = NO
INIT_FUNCTION = ntvfs_cifs_posix_init
SUBSYSTEM = ntvfs
PRIVATE_PROTO_HEADER = cifs_posix_cli/proto.h
# End MODULE ntvfs_cifsposix
################################################

ntvfs_cifsposix_OBJ_FILES = \
	$(addprefix ntvfs/cifs_posix_cli/, vfs_cifs_posix.o svfs_util.o)

################################################
# Start MODULE ntvfs_print
[MODULE::ntvfs_print]
INIT_FUNCTION = ntvfs_print_init 
SUBSYSTEM = ntvfs 
# End MODULE ntvfs_print
################################################

ntvfs_print_OBJ_FILES = ntvfs/print/vfs_print.o

################################################
# Start MODULE ntvfs_ipc
[MODULE::ntvfs_ipc]
SUBSYSTEM = ntvfs
INIT_FUNCTION = ntvfs_ipc_init 
PRIVATE_PROTO_HEADER = ipc/proto.h
PRIVATE_DEPENDENCIES = dcerpc_server DCERPC_COMMON
# End MODULE ntvfs_ipc
################################################

ntvfs_ipc_OBJ_FILES = $(addprefix ntvfs/ipc/, vfs_ipc.o ipc_rap.o rap_server.o)

################################################
# Start MODULE ntvfs_nbench
[MODULE::ntvfs_nbench]
SUBSYSTEM = ntvfs
INIT_FUNCTION = ntvfs_nbench_init 
# End MODULE ntvfs_nbench
################################################

ntvfs_nbench_OBJ_FILES = ntvfs/nbench/vfs_nbench.o

################################################
# Start SUBSYSTEM NTVFS
[SUBSYSTEM::ntvfs]
PRIVATE_PROTO_HEADER = ntvfs_proto.h

ntvfs_OBJ_FILES = $(addprefix ntvfs/, ntvfs_base.o ntvfs_generic.o ntvfs_interface.o ntvfs_util.o)

PUBLIC_HEADERS += ntvfs/ntvfs.h
#
# End SUBSYSTEM NTVFS
################################################
