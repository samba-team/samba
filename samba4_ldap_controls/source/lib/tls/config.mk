################################################
# Start SUBSYSTEM LIBTLS
[SUBSYSTEM::LIBTLS]
ADD_OBJ_FILES = \
		lib/tls/tls.o \
		lib/tls/tlscert.o
REQUIRED_SUBSYSTEMS = \
		LIBTALLOC EXT_LIB_GNUTLS
NOPROTO = YES
#
# End SUBSYSTEM LIBTLS
################################################
