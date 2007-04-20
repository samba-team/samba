# CLDAP server subsystem

#######################
# Start SUBSYSTEM CLDAPD
[MODULE::CLDAPD]
INIT_FUNCTION = server_service_cldapd_init
SUBSYSTEM = service
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		cldap_server.o \
		netlogon.o \
		rootdse.o
PRIVATE_DEPENDENCIES = \
		LIBCLI_CLDAP LIBNETIF process_model
# End SUBSYSTEM CLDAPD
#######################
