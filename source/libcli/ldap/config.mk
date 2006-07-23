#################################
# Start SUBSYSTEM LIBCLI_LDAP
[SUBSYSTEM::LIBCLI_LDAP]
PUBLIC_PROTO_HEADER = ldap_proto.h
PUBLIC_HEADERS = ldap.h
OBJ_FILES = ldap.o \
		ldap_client.o \
		ldap_bind.o \
		ldap_msg.o \
		ldap_ndr.o \
		ldap_ildap.o \
		ldap_controls.o
PUBLIC_DEPENDENCIES = LIBSAMBA-ERRORS LIBEVENTS LIBPACKET
PRIVATE_DEPENDENCIES = LIBCLI_COMPOSITE samba-socket LIBCLI_RESOLVE NDR_SAMR LIBTLS ASN1_UTIL GENSEC_SOCKET
#PRIVATE_DEPENDENCIES = gensec
# End SUBSYSTEM LIBCLI_LDAP
#################################
