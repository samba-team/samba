################################################
# Start SUBSYSTEM LDBSAMBA
[SUBSYSTEM::LDBSAMBA]
PUBLIC_DEPENDENCIES = LIBLDB
PRIVATE_PROTO_HEADER = ldif_handlers.h
PRIVATE_DEPENDENCIES = LIBSECURITY SAMDB_SCHEMA LIBNDR NDR_MISC
# End SUBSYSTEM LDBSAMBA
################################################

LDBSAMBA_OBJ_FILES = $(ldb_sambasrcdir)/ldif_handlers.o

