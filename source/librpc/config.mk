################################################
# Start SUBSYSTEM LIBNDR_RAW
[SUBSYSTEM::LIBNDR_RAW]
INIT_OBJ_FILES = \
		librpc/ndr/ndr.o
ADD_OBJ_FILES = \
		librpc/ndr/ndr_basic.o \
		librpc/ndr/ndr_sec.o \
		librpc/ndr/ndr_spoolss_buf.o
# End SUBSYSTEM LIBNDR_RAW
################################################

################################################
# Start SUBSYSTEM LIBRPC_RAW
[SUBSYSTEM::LIBRPC_RAW]
INIT_OBJ_FILES = \
		librpc/rpc/dcerpc.o
ADD_OBJ_FILES = \
		librpc/rpc/dcerpc_auth.o \
		librpc/rpc/dcerpc_util.o \
		librpc/rpc/dcerpc_error.o \
		librpc/rpc/dcerpc_schannel.o \
		librpc/rpc/dcerpc_ntlm.o \
		librpc/rpc/dcerpc_spnego.o \
		librpc/rpc/dcerpc_smb.o \
		librpc/rpc/dcerpc_sock.o
# End SUBSYSTEM LIBRPC_RAW
################################################

################################################
# Start SUBSYSTEM LIBRPC
[SUBSYSTEM::LIBRPC]
REQUIRED_SUBSYSTEMS = LIBNDR_RAW LIBNDR_GEN LIBRPC_RAW
# End SUBSYSTEM LIBRPC
################################################
