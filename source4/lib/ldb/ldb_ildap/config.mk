################################################
# Start MODULE ldb_ildap
[MODULE::ldb_ildap]
SUBSYSTEM = LIBLDB
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBCLI_LDAP CREDENTIALS
ALIASES = ldapi ldaps ldap
# End MODULE ldb_ildap
################################################

ldb_ildap_OBJ_FILES = lib/ldb/ldb_ildap/ldb_ildap.o

