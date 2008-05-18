##############################
# Start SUBSYSTEM LIBNETIF
[SUBSYSTEM::LIBNETIF]
PRIVATE_PROTO_HEADER = netif_proto.h
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL LIBREPLACE_NETWORK
# End SUBSYSTEM LIBNETIF
##############################

LIBNETIF_OBJ_FILES = $(addprefix $(libsocketsrcdir)/, interface.o netif.o)

################################################
# Start MODULE socket_ip
[MODULE::socket_ip]
SUBSYSTEM = samba-socket
OUTPUT_TYPE = MERGED_OBJ
PRIVATE_DEPENDENCIES = LIBSAMBA-ERRORS LIBREPLACE_NETWORK
# End MODULE socket_ip
################################################

socket_ip_OBJ_FILES = $(libsocketsrcdir)/socket_ip.o

################################################
# Start MODULE socket_unix
[MODULE::socket_unix]
SUBSYSTEM = samba-socket
OUTPUT_TYPE = MERGED_OBJ
PRIVATE_DEPENDENCIES = LIBREPLACE_NETWORK
# End MODULE socket_unix
################################################

socket_unix_OBJ_FILES = $(libsocketsrcdir)/socket_unix.o

################################################
# Start SUBSYSTEM SOCKET
[SUBSYSTEM::samba-socket]
PUBLIC_DEPENDENCIES = LIBTALLOC
PRIVATE_DEPENDENCIES = SOCKET_WRAPPER LIBCLI_COMPOSITE LIBCLI_RESOLVE
# End SUBSYSTEM SOCKET
################################################

samba-socket_OBJ_FILES = $(addprefix $(libsocketsrcdir)/, socket.o access.o connect_multi.o connect.o)

