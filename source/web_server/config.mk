# web server subsystem

#######################
# Start SUBSYSTEM WEB
[MODULE::WEB]
INIT_FUNCTION = server_service_web_init
SUBSYSTEM = smbd
PRIVATE_PROTO_HEADER = proto.h
PRIVATE_DEPENDENCIES = ESP LIBTLS smbcalls process_model 
# End SUBSYSTEM WEB
#######################

WEB_OBJ_FILES = $(addprefix web_server/, web_server.o http.o)
