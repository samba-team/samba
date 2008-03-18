##############################
# Start SUBSYSTEM SOCKET_WRAPPER
[SUBSYSTEM::SOCKET_WRAPPER]
OBJ_FILES = socket_wrapper.o
PRIVATE_DEPENDENCIES = LIBREPLACE_NETWORK
# End SUBSYSTEM SOCKET_WRAPPER
##############################

PUBLIC_HEADERS += lib/socket_wrapper/socket_wrapper.h
