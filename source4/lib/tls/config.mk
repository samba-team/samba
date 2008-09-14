[SUBSYSTEM::LIBTLS]
PUBLIC_DEPENDENCIES = \
		LIBTALLOC GNUTLS LIBSAMBA-HOSTCONFIG samba-socket

LIBTLS_OBJ_FILES = $(addprefix $(libtlssrcdir)/, tls.o tlscert.o)
