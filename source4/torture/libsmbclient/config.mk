#################################
# Start SUBSYSTEM TORTURE_LIBSMBCLIENT
[MODULE::TORTURE_LIBSMBCLIENT]
SUBSYSTEM = smbtorture
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = torture_libsmbclient_init
PRIVATE_DEPENDENCIES = \
		POPT_CREDENTIALS \
		SMBCLIENT
# End SUBSYSTEM TORTURE_LIBSMBCLIENT
#################################

TORTURE_LIBSMBCLIENT_OBJ_FILES = $(addprefix $(torturesrcdir)/libsmbclient/, libsmbclient.o)

$(eval $(call proto_header_template,$(torturesrcdir)/libsmbclient/proto.h,$(TORTURE_LIBSMBCLIENT_OBJ_FILES:.o=.c)))
