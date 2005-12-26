# CLDAP server subsystem

#######################
# Start SUBSYSTEM CLDAPD
[SUBSYSTEM::CLDAPD]
OBJ_FILES = \
		cldap_server.o \
		netlogon.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_CLDAP
# End SUBSYSTEM CLDAPD
#######################
