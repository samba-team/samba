# web server subsystem

#######################
# Start SUBSYSTEM WEB
[SUBSYSTEM::WEB]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		web_server.o \
		http.o
REQUIRED_SUBSYSTEMS = ESP LIBTLS smbcalls
# End SUBSYSTEM WEB
#######################
