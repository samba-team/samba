#################################
# Start SUBSYSTEM TORTURE_LOCAL
[MODULE::TORTURE_LOCAL]
SUBSYSTEM = torture
INIT_FUNCTION = torture_local_init
PRIVATE_PROTO_HEADER = \
		proto.h
OBJ_FILES = \
		iconv.o \
		../../lib/crypto/md4test.o \
		../../lib/crypto/md5test.o \
		../../lib/crypto/hmacmd5test.o \
		../../lib/crypto/sha1test.o \
		../../lib/crypto/hmacsha1test.o \
		../../lib/talloc/testsuite.o \
		../../lib/replace/test/os2_delete.o \
		../../lib/replace/test/testsuite.o \
		messaging.o \
		../../librpc/tests/binding_string.o \
		../../lib/util/tests/idtree.o \
		../../lib/socket/testsuite.o \
		irpc.o \
		../../lib/registry/tests/generic.o \
		resolve.o \
		../../lib/util/tests/strlist.o \
		../../lib/util/tests/file.o \
		sddl.o \
		../../lib/tdr/testsuite.o \
		event.o \
		local.o \
		dbspeed.o \
		torture.o
PUBLIC_DEPENDENCIES = \
		RPC_NDR_ECHO \
		TDR \
		LIBCLI_SMB \
		MESSAGING \
		ICONV \
		registry \
		LIBCRYPTO \
		POPT_CREDENTIALS \
		TORTURE_AUTH \
		TORTURE_UTIL
PRIVATE_DEPENDENCIES = TORTURE_NDR
# End SUBSYSTEM TORTURE_LOCAL
#################################

