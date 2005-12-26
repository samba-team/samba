
################################################
# Start MODULE socket_ipv4
[MODULE::socket_ipv4]
SUBSYSTEM = SOCKET
OBJ_FILES = \
		socket_ipv4.o
NOPROTO=YES
# End MODULE socket_ipv4
################################################

################################################
# Start MODULE socket_ipv6
[MODULE::socket_ipv6]
SUBSYSTEM = SOCKET
OBJ_FILES = \
		socket_ipv6.o
NOPROTO=YES
# End MODULE socket_ipv6
################################################

################################################
# Start MODULE socket_unix
[MODULE::socket_unix]
SUBSYSTEM = SOCKET
OBJ_FILES = \
		socket_unix.o
NOPROTO=YES
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
NOPROTO=YES
# End SUBSYSTEM SOCKET
################################################
