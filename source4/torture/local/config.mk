#################################
# Start SUBSYSTEM TORTURE_LOCAL
[MODULE::TORTURE_LOCAL]
SUBSYSTEM = torture
INIT_FUNCTION = torture_local_init
PRIVATE_PROTO_HEADER = \
		proto.h
PRIVATE_DEPENDENCIES = \
		RPC_NDR_ECHO \
		TDR \
		LIBCLI_SMB \
		MESSAGING \
		ICONV \
		POPT_CREDENTIALS \
		TORTURE_AUTH \
		TORTURE_UTIL \
		TORTURE_NDR \
		share \
		torture_registry
# End SUBSYSTEM TORTURE_LOCAL
#################################

TORTURE_LOCAL_OBJ_FILES = \
		lib/charset/tests/iconv.o \
		lib/talloc/testsuite.o \
		lib/replace/test/getifaddrs.o \
		lib/replace/test/os2_delete.o \
		lib/replace/test/strptime.o \
		lib/replace/test/testsuite.o \
		lib/messaging/tests/messaging.o \
		lib/messaging/tests/irpc.o \
		librpc/tests/binding_string.o \
		lib/util/tests/idtree.o \
		lib/socket/testsuite.o \
		lib/socket_wrapper/testsuite.o \
		libcli/resolve/testsuite.o \
		lib/util/tests/strlist.o \
		lib/util/tests/str.o \
		lib/util/tests/file.o \
		lib/util/tests/genrand.o \
		lib/compression/testsuite.o \
		lib/charset/tests/charset.o \
		libcli/security/tests/sddl.o \
		lib/tdr/testsuite.o \
		lib/events/testsuite.o \
		param/tests/share.o \
		param/tests/loadparm.o \
		auth/credentials/tests/simple.o \
		torture/local/local.o \
		torture/local/dbspeed.o \
		torture/local/torture.o

