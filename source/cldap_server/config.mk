# CLDAP server subsystem

#######################
# Start SUBSYSTEM CLDAPD
[SUBSYSTEM::CLDAPD]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		cldap_server.o \
		netlogon.o
PUBLIC_DEPENDENCIES = \
		LIBCLI_CLDAP LIBNETIF process_model
# End SUBSYSTEM CLDAPD
#######################
