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
# Start MODULE socket_ipv4
[MODULE::socket_ipv4]
SUBSYSTEM = samba-socket
OUTPUT_TYPE = INTEGRATED
OBJ_FILES = \
		socket_ipv4.o
PRIVATE_DEPENDENCIES = EXT_SOCKET EXT_NSL LIBSAMBA-ERRORS 
# End MODULE socket_ipv4
################################################

################################################
# Start MODULE socket_ipv6
[MODULE::socket_ipv6]
SUBSYSTEM = samba-socket
OUTPUT_TYPE = INTEGRATED
OBJ_FILES = \
		socket_ipv6.o
PRIVATE_DEPENDENCIES = EXT_SOCKET EXT_NSL
# End MODULE socket_ipv6
################################################

################################################
# Start MODULE socket_unix
[MODULE::socket_unix]
SUBSYSTEM = samba-socket
OUTPUT_TYPE = INTEGRATED
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
LDFLAGS = $(SUBSYSTEM_LIBCLI_RESOLVE_OUTPUT) $(SUBSYSTEM_LIBCLI_NBT_OUTPUT) $(SUBSYSTEM_NDR_NBT_OUTPUT) $(LIBRARY_NDR_SVCCTL_OUTPUT)
PUBLIC_DEPENDENCIES = LIBTALLOC
PRIVATE_DEPENDENCIES = SOCKET_WRAPPER LIBCLI_COMPOSITE 
#LIBCLI_RESOLVE
# End SUBSYSTEM SOCKET
################################################
