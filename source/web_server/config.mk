# web server subsystem

#######################
# Start SUBSYSTEM WEB
[SUBSYSTEM::WEB]
INIT_OBJ_FILES = \
		web_server/web_server.o
ADD_OBJ_FILES = \
		web_server/http.o
REQUIRED_SUBSYSTEMS = ESP LIBTLS SMBCALLS
# End SUBSYSTEM WEB
#######################
