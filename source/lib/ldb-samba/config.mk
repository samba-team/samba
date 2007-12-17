################################################
# Start SUBSYSTEM LDBSAMBA
[SUBSYSTEM::LDBSAMBA]
PUBLIC_DEPENDENCIES = LIBLDB
PRIVATE_PROTO_HEADER = ldif_handlers.h
PRIVATE_DEPENDENCIES = LIBSECURITY SAMDB_SCHEMA LIBNDR NDR_MISC
OBJ_FILES = \
		ldif_handlers.o
# End SUBSYSTEM LDBSAMBA
################################################


