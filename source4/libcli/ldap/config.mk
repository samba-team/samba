[SUBSYSTEM::LIBCLI_LDAP_MESSAGE]
PUBLIC_DEPENDENCIES = LIBSAMBA-ERRORS LIBTALLOC LIBLDB
PRIVATE_DEPENDENCIES = ASN1_UTIL

LIBCLI_LDAP_MESSAGE_OBJ_FILES = $(addprefix $(libclisrcdir)/ldap/, \
						ldap_message.o)
PUBLIC_HEADERS += $(libclisrcdir)/ldap/ldap_message.h

[SUBSYSTEM::LIBCLI_LDAP]
PUBLIC_DEPENDENCIES = LIBSAMBA-ERRORS LIBTEVENT LIBPACKET
PRIVATE_DEPENDENCIES = LIBCLI_COMPOSITE samba_socket NDR_SAMR LIBTLS \
		       LDAP_ENCODE LIBNDR LP_RESOLVE gensec LIBCLI_LDAP_MESSAGE

LIBCLI_LDAP_OBJ_FILES = $(addprefix $(libclisrcdir)/ldap/, \
					   ldap_client.o ldap_bind.o \
					   ldap_ildap.o ldap_controls.o)
PUBLIC_HEADERS += $(libclisrcdir)/ldap/ldap.h

$(eval $(call proto_header_template,$(libclisrcdir)/ldap/ldap_proto.h,$(LIBCLI_LDAP_OBJ_FILES:.o=.c)))

[SUBSYSTEM::LDAP_ENCODE]
PRIVATE_DEPENDENCIES = LIBLDB

LDAP_ENCODE_OBJ_FILES = $(libclisrcdir)/ldap/ldap_ndr.o
PUBLIC_HEADERS += $(libclisrcdir)/ldap/ldap_ndr.h
