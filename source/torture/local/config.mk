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
REQUIRED_SUBSYSTEMS = \
		RPC_NDR_ECHO \
		LIBSMB \
		MESSAGING \
		registry
# End SUBSYSTEM TORTURE_LOCAL
#################################

