################################################
# Start SUBSYSTEM LIBTLS
[SUBSYSTEM::LIBTLS]
OBJ_FILES = \
		tls.o \
		tlscert.o
REQUIRED_SUBSYSTEMS = \
		LIBTALLOC EXT_LIB_GNUTLS
NOPROTO = YES
#
# End SUBSYSTEM LIBTLS
################################################
