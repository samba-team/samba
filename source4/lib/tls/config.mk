################################################
# Start SUBSYSTEM LIBTLS
[SUBSYSTEM::LIBTLS]
PUBLIC_DEPENDENCIES = \
		LIBTALLOC GNUTLS LIBSAMBA-CONFIG samba-socket

LIBTLS_OBJ_FILES = lib/tls/tls.o lib/tls/tlscert.o
