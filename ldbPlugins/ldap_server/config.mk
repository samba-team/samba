# LDAP server subsystem

#######################
# Start SUBSYSTEM LDAP
[SUBSYSTEM::LDAP]
INIT_OBJ_FILES = \
		ldap_server/ldap_server.o \
		ldap_server/ldap_backend.o \
		ldap_server/ldap_bind.o \
		ldap_server/ldap_rootdse.o \
		ldap_server/ldap_parse.o \
		ldap_server/ldap_simple_ldb.o
REQUIRED_SUBSYSTEMS = \
		LIBCLI_LDAP SAMDB
# End SUBSYSTEM SMB
#######################
