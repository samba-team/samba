[SUBSYSTEM::LIBCLI_LDAP]
PRIVATE_PROTO_HEADER = ldap_proto.h
PUBLIC_DEPENDENCIES = LIBSAMBA-ERRORS LIBEVENTS LIBPACKET 
PRIVATE_DEPENDENCIES = LIBCLI_COMPOSITE samba-socket NDR_SAMR LIBTLS ASN1_UTIL \
					   LDAP_ENCODE LIBNDR LP_RESOLVE gensec

LIBCLI_LDAP_OBJ_FILES = $(addprefix libcli/ldap/, \
					   ldap.o ldap_client.o ldap_bind.o \
					   ldap_msg.o ldap_ildap.o ldap_controls.o)


PUBLIC_HEADERS += libcli/ldap/ldap.h libcli/ldap/ldap_ndr.h

[SUBSYSTEM::LDAP_ENCODE]
# FIXME PRIVATE_DEPENDENCIES = LIBLDB

LDAP_ENCODE_OBJ_FILES = libcli/ldap/ldap_ndr.o
