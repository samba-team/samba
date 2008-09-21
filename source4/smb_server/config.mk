# SMB server subsystem
#
[MODULE::SERVICE_SMB]
INIT_FUNCTION = server_service_smb_init
SUBSYSTEM = samba
PRIVATE_DEPENDENCIES = SMB_SERVER

SERVICE_SMB_OBJ_FILES = $(smb_serversrcdir)/smb_server.o

$(eval $(call proto_header_template,$(smb_serversrcdir)/service_smb_proto.h,$(SERVICE_SMB_OBJ_FILES:.o=.c)))

#######################
# Start SUBSYSTEM SMB
[SUBSYSTEM::SMB_SERVER]
PUBLIC_DEPENDENCIES = \
		share \
		LIBPACKET \
		SMB_PROTOCOL \
		SMB2_PROTOCOL
# End SUBSYSTEM SMB
#######################

SMB_SERVER_OBJ_FILES = $(addprefix $(smb_serversrcdir)/, \
		handle.o \
		tcon.o \
		session.o \
		blob.o \
		management.o)

$(eval $(call proto_header_template,$(smb_serversrcdir)/smb_server_proto.h,$(SMB_SERVER_OBJ_FILES:.o=.c)))

mkinclude smb/config.mk
mkinclude smb2/config.mk
