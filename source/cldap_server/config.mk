# CLDAP server subsystem

#######################
# Start SUBSYSTEM CLDAPD
[SUBSYSTEM::CLDAPD]
INIT_OBJ_FILES = \
		cldap_server.o
ADD_OBJ_FILES = \
		netlogon.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_CLDAP
# End SUBSYSTEM CLDAPD
#######################
