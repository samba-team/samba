#################################
# Start SUBSYSTEM TORTURE_LOCAL
[SUBSYSTEM::TORTURE_LOCAL]
ADD_OBJ_FILES = \
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
		sddl.o
REQUIRED_SUBSYSTEMS = \
		LIBSMB \
		MESSAGING \
		REGISTRY
# End SUBSYSTEM TORTURE_LOCAL
#################################

