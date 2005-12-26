# web server subsystem

#######################
# Start SUBSYSTEM WEB
[SUBSYSTEM::WEB]
OBJ_FILES = \
		web_server.o \
		http.o
REQUIRED_SUBSYSTEMS = ESP LIBTLS SMBCALLS
# End SUBSYSTEM WEB
#######################
