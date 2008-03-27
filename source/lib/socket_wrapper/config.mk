##############################
# Start SUBSYSTEM SOCKET_WRAPPER
[SUBSYSTEM::SOCKET_WRAPPER]
PRIVATE_DEPENDENCIES = LIBREPLACE_NETWORK
# End SUBSYSTEM SOCKET_WRAPPER
##############################

PUBLIC_HEADERS += lib/socket_wrapper/socket_wrapper.h

SOCKET_WRAPPER_OBJ_FILES = lib/socket_wrapper/socket_wrapper.o
