#################################
# Start SUBSYSTEM TORTURE_LOCAL
[MODULE::TORTURE_LOCAL]
SUBSYSTEM = smbtorture
INIT_FUNCTION = torture_local_init
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
		$(torturesrcdir)/../lib/charset/tests/iconv.o \
		$(torturesrcdir)/../../talloc/testsuite.o \
		$(torturesrcdir)/../../replace/test/getifaddrs.o \
		$(torturesrcdir)/../../replace/test/os2_delete.o \
		$(torturesrcdir)/../../replace/test/strptime.o \
		$(torturesrcdir)/../../replace/test/testsuite.o \
		$(torturesrcdir)/../lib/messaging/tests/messaging.o \
		$(torturesrcdir)/../lib/messaging/tests/irpc.o \
		$(torturesrcdir)/../librpc/tests/binding_string.o \
		$(torturesrcdir)/../lib/util/tests/idtree.o \
		$(torturesrcdir)/../lib/socket/testsuite.o \
		$(torturesrcdir)/../../socket_wrapper/testsuite.o \
		$(torturesrcdir)/../libcli/resolve/testsuite.o \
		$(torturesrcdir)/../lib/util/tests/strlist.o \
		$(torturesrcdir)/../lib/util/tests/str.o \
		$(torturesrcdir)/../lib/util/tests/file.o \
		$(torturesrcdir)/../lib/util/tests/genrand.o \
		$(torturesrcdir)/../../compression/testsuite.o \
		$(torturesrcdir)/../lib/charset/tests/charset.o \
		$(torturesrcdir)/../libcli/security/tests/sddl.o \
		$(torturesrcdir)/../lib/tdr/testsuite.o \
		$(torturesrcdir)/../lib/events/testsuite.o \
		$(torturesrcdir)/../param/tests/share.o \
		$(torturesrcdir)/../param/tests/loadparm.o \
		$(torturesrcdir)/../auth/credentials/tests/simple.o \
		$(torturesrcdir)/local/local.o \
		$(torturesrcdir)/local/dbspeed.o \
		$(torturesrcdir)/local/torture.o


$(eval $(call proto_header_template,$(torturesrcdir)/local/proto.h,$(TORTURE_LOCAL_OBJ_FILES:.o=.c)))
