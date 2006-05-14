#################################
# Start SUBSYSTEM TORTURE_LOCAL
[SUBSYSTEM::TORTURE_LOCAL]
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
		ndr.o
PUBLIC_DEPENDENCIES = \
		RPC_NDR_ECHO \
		LIBCLI_SMB \
		MESSAGING \
		ICONV \
		registry \
		POPT_CREDENTIALS
# End SUBSYSTEM TORTURE_LOCAL
#################################

