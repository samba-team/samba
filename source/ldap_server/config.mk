# LDAP server subsystem

#######################
# Start SUBSYSTEM LDAP
[SUBSYSTEM::LDAP]
INIT_OBJ_FILES = \
		ldap_server/ldap_server.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_LDAP
# End SUBSYSTEM SMB
#######################
