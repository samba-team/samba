################################################
# Start MODULE ldb_ildap
[MODULE::ldb_ildap]
SUBSYSTEM = LIBLDB
CFLAGS = -Ilib/ldb/include
OUTPUT_TYPE = SHARED_LIBRARY
PRIVATE_DEPENDENCIES = LIBTALLOC LIBCLI_LDAP CREDENTIALS
ALIASES = ldapi ldaps ldap
OBJ_FILES = \
		ldb_ildap.o
# End MODULE ldb_ildap
################################################


