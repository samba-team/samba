
################################################
# Start MODULE socket_ipv4
[MODULE::socket_ipv4]
SUBSYSTEM = SOCKET
INIT_OBJ_FILES = \
		lib/socket/socket_ipv4.o
# End MODULE socket_ipv4
################################################

################################################
# Start MODULE socket_ipv6
[MODULE::socket_ipv6]
SUBSYSTEM = SOCKET
INIT_OBJ_FILES = \
		lib/socket/socket_ipv6.o
# End MODULE socket_ipv6
################################################

################################################
# Start MODULE socket_unix
[MODULE::socket_unix]
SUBSYSTEM = SOCKET
INIT_OBJ_FILES = \
		lib/socket/socket_unix.o
# End MODULE socket_unix
################################################

################################################
# Start SUBSYSTEM SOCKET
[SUBSYSTEM::SOCKET]
INIT_OBJ_FILES = \
		lib/socket/socket.o
ADD_OBJ_FILES = \
		lib/socket/access.o
# End SUBSYSTEM SOCKET
################################################
