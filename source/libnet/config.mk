#################################
# Start SUBSYSTEM LIBNET
[SUBSYSTEM::LIBNET]
INIT_OBJ_FILES = \
		libnet/libnet.o
ADD_OBJ_FILES = \
		libnet/libnet_passwd.o \
		libnet/libnet_time.o \
		libnet/libnet_rpc.o
REQUIRED_SUBSYSTEMS = LIBRPC
# End SUBSYSTEM LIBNET
#################################
