# web server subsystem

#######################
# Start SUBSYSTEM WEB
[MODULE::WEB]
INIT_FUNCTION = server_service_web_init
SUBSYSTEM = service
PRIVATE_PROTO_HEADER = proto.h
OBJ_FILES = \
		web_server.o \
		http.o
PUBLIC_DEPENDENCIES = ESP LIBTLS smbcalls process_model 
# End SUBSYSTEM WEB
#######################
