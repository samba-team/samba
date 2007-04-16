# NTVFS Server subsystem
include posix/config.mk
include common/config.mk
include unixuid/config.mk
include sysdep/config.mk

################################################
# Start MODULE ntvfs_cifs
[MODULE::ntvfs_cifs]
INIT_FUNCTION = ntvfs_cifs_init 
SUBSYSTEM = ntvfs
OBJ_FILES = \
		cifs/vfs_cifs.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_SMB LIBCLI_RAW
# End MODULE ntvfs_cifs
################################################

################################################
# Start MODULE ntvfs_simple
[MODULE::ntvfs_simple]
INIT_FUNCTION = ntvfs_simple_init 
SUBSYSTEM = ntvfs 
PRIVATE_PROTO_HEADER = simple/proto.h
OBJ_FILES = \
		simple/vfs_simple.o \
		simple/svfs_util.o
# End MODULE ntvfs_simple
################################################

################################################
# Start MODULE ntvfs_cifsposix
[MODULE::ntvfs_cifsposix]
#ENABLE = NO
INIT_FUNCTION = ntvfs_cifs_posix_init
SUBSYSTEM = ntvfs
PRIVATE_PROTO_HEADER = cifs_posix_cli/proto.h
OBJ_FILES = \
                cifs_posix_cli/vfs_cifs_posix.o \
                cifs_posix_cli/svfs_util.o
# End MODULE ntvfs_cifsposix
################################################

################################################
# Start MODULE ntvfs_print
[MODULE::ntvfs_print]
INIT_FUNCTION = ntvfs_print_init 
SUBSYSTEM = ntvfs 
OBJ_FILES = \
		print/vfs_print.o
# End MODULE ntvfs_print
################################################

################################################
# Start MODULE ntvfs_ipc
[MODULE::ntvfs_ipc]
SUBSYSTEM = ntvfs
INIT_FUNCTION = ntvfs_ipc_init 
PRIVATE_PROTO_HEADER = ipc/proto.h
OBJ_FILES = \
		ipc/vfs_ipc.o \
		ipc/ipc_rap.o \
		ipc/rap_server.o
PUBLIC_DEPENDENCIES = dcerpc_server DCERPC_COMMON
# End MODULE ntvfs_ipc
################################################


################################################
# Start MODULE ntvfs_nbench
[MODULE::ntvfs_nbench]
SUBSYSTEM = ntvfs
INIT_FUNCTION = ntvfs_nbench_init 
OBJ_FILES = \
		nbench/vfs_nbench.o
# End MODULE ntvfs_nbench
################################################


################################################
# Start SUBSYSTEM NTVFS
[LIBRARY::ntvfs]
PUBLIC_HEADERS = ntvfs.h
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Virtual File System with NTFS semantics
PRIVATE_PROTO_HEADER = ntvfs_proto.h
OBJ_FILES = \
		ntvfs_base.o \
		ntvfs_generic.o \
		ntvfs_interface.o \
		ntvfs_util.o
PRIVATE_DEPENDENCIES = auth
#
# End SUBSYSTEM NTVFS
################################################
