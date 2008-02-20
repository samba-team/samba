##############################
# Start SUBSYSTEM LIBNETIF
[SUBSYSTEM::LIBNETIF]
PRIVATE_PROTO_HEADER = netif_proto.h
OBJ_FILES = \
		interface.o \
		netif.o
PRIVATE_DEPENDENCIES = LIBSAMBA-UTIL EXT_SOCKET EXT_NSL
# End SUBSYSTEM LIBNETIF
##############################

################################################
# Start MODULE socket_ip
[MODULE::socket_ip]
SUBSYSTEM = samba-socket
OUTPUT_TYPE = MERGED_OBJ
OBJ_FILES = \
		socket_ip.o
PRIVATE_DEPENDENCIES = EXT_SOCKET EXT_NSL LIBSAMBA-ERRORS 
# End MODULE socket_ip
################################################

################################################
# Start MODULE socket_unix
[MODULE::socket_unix]
SUBSYSTEM = samba-socket
OUTPUT_TYPE = MERGED_OBJ
OBJ_FILES = \
		socket_unix.o
PRIVATE_DEPENDENCIES = EXT_SOCKET EXT_NSL
# End MODULE socket_unix
################################################

################################################
# Start SUBSYSTEM SOCKET
[SUBSYSTEM::samba-socket]
OBJ_FILES = \
		socket.o \
		access.o \
		connect_multi.o \
		connect.o
PUBLIC_DEPENDENCIES = LIBTALLOC
PRIVATE_DEPENDENCIES = SOCKET_WRAPPER LIBCLI_COMPOSITE LIBCLI_RESOLVE
# End SUBSYSTEM SOCKET
################################################
