# CLDAP server subsystem

#######################
# Start SUBSYSTEM CLDAPD
[SUBSYSTEM::CLDAPD]
INIT_OBJ_FILES = \
		cldap_server/cldap_server.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_CLDAP
# End SUBSYSTEM CLDAPD
#######################
