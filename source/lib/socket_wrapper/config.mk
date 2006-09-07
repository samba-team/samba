##############################
# Start SUBSYSTEM SOCKET_WRAPPER
[LIBRARY::SOCKET_WRAPPER]
VERSION = 0.0.1
SO_VERSION = 0
DESCRIPTION = Wrapper library for testing TCP/IP connections using Unix Sockets
PUBLIC_HEADERS = socket_wrapper.h
OBJ_FILES = socket_wrapper.o
PRIVATE_DEPENDENCIES = EXT_SOCKET
# End SUBSYSTEM SOCKET_WRAPPER
##############################
