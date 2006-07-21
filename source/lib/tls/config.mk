################################################
# Start SUBSYSTEM LIBTLS
[SUBSYSTEM::LIBTLS]
OBJ_FILES = \
		tls.o \
		tlscert.o
PUBLIC_DEPENDENCIES = \
		LIBTALLOC GNUTLS LIBSAMBA-CONFIG samba-socket
#
# End SUBSYSTEM LIBTLS
################################################
