# CLDAP server subsystem

#######################
# Start SUBSYSTEM CLDAPD
[MODULE::CLDAPD]
INIT_FUNCTION = server_service_cldapd_init
SUBSYSTEM = service
PRIVATE_DEPENDENCIES = \
		LIBCLI_CLDAP LIBNETIF process_model
# End SUBSYSTEM CLDAPD
#######################

CLDAPD_OBJ_FILES = $(addprefix $(cldap_serversrcdir)/, \
		cldap_server.o \
		netlogon.o \
		rootdse.o)

$(eval $(call proto_header_template,$(cldap_serversrcdir)/proto.h,$(CLDAPD_OBJ_FILES:.o=.c)))
