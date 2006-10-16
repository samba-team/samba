#################################
# Start SUBSYSTEM TORTURE_LOCAL
[MODULE::TORTURE_LOCAL]
SUBSYSTEM = torture
INIT_FUNCTION = torture_local_init
PRIVATE_PROTO_HEADER = \
		proto.h
OBJ_FILES = \
		iconv.o \
		../../lib/replace/test/testsuite.o \
		../../lib/replace/test/os2_delete.o \
		../../lib/crypto/md4test.o \
		../../lib/crypto/md5test.o \
		../../lib/crypto/hmacmd5test.o \
		../../lib/crypto/sha1test.o \
		../../lib/crypto/hmacsha1test.o \
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
		local.o \
		dbspeed.o \
		torture.o
PUBLIC_DEPENDENCIES = \
		RPC_NDR_ECHO \
		LIBCLI_SMB \
		MESSAGING \
		ICONV \
		registry \
		LIBCRYPTO \
		POPT_CREDENTIALS \
		TORTURE_UI
# End SUBSYSTEM TORTURE_LOCAL
#################################

