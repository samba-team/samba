[SUBSYSTEM::LIBCLI_LDAP_MESSAGE]
PUBLIC_DEPENDENCIES = LIBSAMBA-ERRORS LIBTALLOC LIBLDB
PRIVATE_DEPENDENCIES = ASN1_UTIL

LIBCLI_LDAP_MESSAGE_OBJ_FILES = $(addprefix ../libcli/ldap/, \
						ldap_message.o)
PUBLIC_HEADERS += ../libcli/ldap/ldap_message.h ../libcli/ldap/ldap_errors.h
