# LDAP server subsystem

#######################
# Start SUBSYSTEM LDAP
[MODULE::LDAP]
INIT_FUNCTION = server_service_ldap_init
SUBSYSTEM = service
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		ldap_server.o \
		ldap_backend.o \
		ldap_bind.o \
		ldap_extended.o
PRIVATE_DEPENDENCIES = CREDENTIALS \
		LIBCLI_LDAP SAMDB \
		process_model auth \
		GENSEC_SOCKET
# End SUBSYSTEM SMB
#######################
