################################################
# Start SUBSYSTEM LIBTLS
[SUBSYSTEM::LIBTLS]
OBJ_FILES = \
		tls.o \
		tlscert.o
REQUIRED_SUBSYSTEMS = \
		LIBTALLOC EXT_LIB_GNUTLS LIBSAMBA-CONFIG
#
# End SUBSYSTEM LIBTLS
################################################
