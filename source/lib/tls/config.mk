################################################
# Start SUBSYSTEM LIBTLS
[SUBSYSTEM::LIBTLS]
OBJ_FILES = \
		tls.o \
		tlscert.o
PUBLIC_DEPENDENCIES = \
		LIBTALLOC GNUTLS LIBSAMBA-HOSTCONFIG samba-socket
#
# End SUBSYSTEM LIBTLS
################################################
