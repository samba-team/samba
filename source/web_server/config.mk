# web server subsystem

#######################
# Start SUBSYSTEM WEB
[SUBSYSTEM::WEB]
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		web_server.o \
		http.o
PUBLIC_DEPENDENCIES = ESP LIBTLS smbcalls process_model
# End SUBSYSTEM WEB
#######################
