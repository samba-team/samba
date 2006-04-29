
################################################
# Start MODULE socket_ipv4
[MODULE::socket_ipv4]
SUBSYSTEM = SOCKET
OUTPUT_TYPE = INTEGRATED
OBJ_FILES = \
		socket_ipv4.o
PUBLIC_DEPENDENCIES = EXT_SOCKET
PRIVATE_DEPENDENCIES = LIBSAMBA-ERRORS
# End MODULE socket_ipv4
################################################

################################################
# Start MODULE socket_ipv6
[MODULE::socket_ipv6]
SUBSYSTEM = SOCKET
OUTPUT_TYPE = INTEGRATED
OBJ_FILES = \
		socket_ipv6.o
PUBLIC_DEPENDENCIES = EXT_SOCKET
# End MODULE socket_ipv6
################################################

################################################
# Start MODULE socket_unix
[MODULE::socket_unix]
SUBSYSTEM = SOCKET
OUTPUT_TYPE = INTEGRATED
OBJ_FILES = \
		socket_unix.o
PUBLIC_DEPENDENCIES = EXT_SOCKET
# End MODULE socket_unix
################################################

################################################
# Start SUBSYSTEM SOCKET
[SUBSYSTEM::SOCKET]
OBJ_FILES = \
		socket.o \
		access.o \
		connect_multi.o \
		connect.o
LDFLAGS = $(LIBRARY_LIBCLI_RESOLVE_OUTPUT) $(LIBRARY_LIBCLI_NBT_OUTPUT) $(SUBSYSTEM_NDR_NBT_OUTPUT) $(SUBSYSTEM_NDR_SVCCTL_OUTPUT)
PUBLIC_DEPENDENCIES = LIBTALLOC
PRIVATE_DEPENDENCIES = SOCKET_WRAPPER LIBCLI_COMPOSITE 
#LIBCLI_RESOLVE
# End SUBSYSTEM SOCKET
################################################
