# CLDAP server subsystem

#######################
# Start SUBSYSTEM CLDAPD
[MODULE::CLDAPD]
INIT_FUNCTION = server_service_cldapd_init
SUBSYSTEM = service
PRIVATE_PROTO_HEADER = proto.h
PRIVATE_DEPENDENCIES = \
		LIBCLI_CLDAP LIBNETIF process_model
# End SUBSYSTEM CLDAPD
#######################

CLAPD_OBJ_FILES = $(addprefix cldap_server, \
		cldap_server.o \
		netlogon.o \
		rootdse.o)

