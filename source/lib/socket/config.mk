
################################################
# Start MODULE socket_ipv4
[MODULE::socket_ipv4]
INIT_OBJ_FILES = \
		lib/socket/socket_ipv4.o
# End MODULE socket_ipv4
################################################

################################################
# Start SUBSYSTEM SOCKET
[SUBSYSTEM::SOCKET]
INIT_OBJ_FILES = \
		lib/socket/socket.o
# End SUBSYSTEM SOCKET
################################################
