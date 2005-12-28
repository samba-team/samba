#################################
# Start SUBSYSTEM LIBCLI_LDAP
[SUBSYSTEM::LIBCLI_LDAP]
PRIVATE_PROTO_HEADER = ldap_proto.h
OBJ_FILES = ldap.o \
		ldap_client.o \
		ldap_bind.o \
		ldap_msg.o \
		ldap_ndr.o \
		ldap_ildap.o
REQUIRED_SUBSYSTEMS = LIBCLI_UTILS LIBEVENTS GENSEC SOCKET RPC_NDR_SAMR LIBTLS
# End SUBSYSTEM LIBCLI_LDAP
#################################
