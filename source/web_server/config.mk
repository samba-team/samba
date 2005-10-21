# web server subsystem

#######################
# Start SUBSYSTEM WEB
[SUBSYSTEM::WEB]
INIT_OBJ_FILES = \
		web_server.o
ADD_OBJ_FILES = \
		http.o
REQUIRED_SUBSYSTEMS = ESP LIBTLS SMBCALLS
# End SUBSYSTEM WEB
#######################
