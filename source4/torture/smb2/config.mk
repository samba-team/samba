
#################################
# Start SUBSYSTEM TORTURE_SMB2
[MODULE::TORTURE_SMB2]
SUBSYSTEM = smbtorture
OUTPUT_TYPE = MERGED_OBJ
INIT_FUNCTION = torture_smb2_init
PRIVATE_DEPENDENCIES = \
		LIBCLI_SMB2 POPT_CREDENTIALS torture
# End SUBSYSTEM TORTURE_SMB2
#################################

TORTURE_SMB2_OBJ_FILES = $(addprefix $(torturesrcdir)/smb2/, \
		connect.o \
		scan.o \
		util.o \
		getinfo.o \
		setinfo.o \
		find.o \
		lock.o \
		notify.o \
		smb2.o \
		persistent_handles.o \
		oplocks.o \
		create.o \
		read.o)


$(eval $(call proto_header_template,$(torturesrcdir)/smb2/proto.h,$(TORTURE_SMB2_OBJ_FILES:.o=.c)))
