#################################
# Start SUBSYSTEM LIBCLI_LDAP
[SUBSYSTEM::LIBCLI_LDAP]
ADD_OBJ_FILES = libcli/ldap/ldap.o \
		libcli/ldap/ldap_client.o \
		libcli/ldap/ldap_ldif.o \
		libcli/ldap/ldap_ndr.o
NOPROTO=YES
# End SUBSYSTEM LIBCLI_LDAP
#################################
