#################################
# Start SUBSYSTEM TORTURE_LOCAL
[MODULE::TORTURE_LOCAL]
SUBSYSTEM = torture
INIT_FUNCTION = torture_local_init
PRIVATE_PROTO_HEADER = \
		proto.h
OBJ_FILES = \
		iconv.o \
		../../lib/talloc/testsuite.o \
		messaging.o \
		binding_string.o \
		idtree.o \
		socket.o \
		irpc.o \
		registry.o \
		resolve.o \
		util_strlist.o \
		util_file.o \
		sddl.o \
		ndr.o \
		event.o \
		local.o
PUBLIC_DEPENDENCIES = \
		RPC_NDR_ECHO \
		LIBCLI_SMB \
		MESSAGING \
		ICONV \
		registry \
		POPT_CREDENTIALS \
		TORTURE_UI
# End SUBSYSTEM TORTURE_LOCAL
#################################

