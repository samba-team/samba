#################################
# Start SUBSYSTEM LIBCLI_LDAP
[SUBSYSTEM::LIBCLI_LDAP]
PRIVATE_PROTO_HEADER = ldap_proto.h
OBJ_FILES = ldap.o \
		ldap_client.o \
		ldap_bind.o \
		ldap_msg.o \
		ldap_ndr.o \
		ldap_ildap.o \
		ldap_controls.o
REQUIRED_SUBSYSTEMS = LIBCLI_UTILS LIBEVENTS gensec SOCKET NDR_SAMR LIBTLS \
					  LIBPACKET
# End SUBSYSTEM LIBCLI_LDAP
#################################
