# LDAP server subsystem

#######################
# Start SUBSYSTEM LDAP
[SUBSYSTEM::LDAP]
OBJ_FILES = \
		ldap_server.o \
		ldap_backend.o \
		ldap_bind.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_LDAP SAMDB
# End SUBSYSTEM SMB
#######################
