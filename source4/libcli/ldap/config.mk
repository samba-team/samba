#################################
# Start SUBSYSTEM LIBCLI_LDAP
[SUBSYSTEM::LIBCLI_LDAP]
ADD_OBJ_FILES = libcli/ldap/ldap.o \
		libcli/ldap/ldap_client.o \
		libcli/ldap/ldap_bind.o \
		libcli/ldap/ldap_msg.o \
		libcli/ldap/ldap_ndr.o \
		libcli/ldap/ldap_ildap.o
REQUIRED_SUBSYSTEMS = LIBCLI_UTILS LIBBASIC LIBEVENTS GENSEC SOCKET RPC_NDR_SAMR
# End SUBSYSTEM LIBCLI_LDAP
#################################
