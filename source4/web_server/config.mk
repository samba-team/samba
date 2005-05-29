# web server subsystem

#######################
# Start SUBSYSTEM ESP
[SUBSYSTEM::ESP]
ADD_OBJ_FILES = \
		web_server/esp/esp.o  \
		web_server/esp/espProcs.o
REQUIRED_SUBSYSTEMS = EJS
NOPROTO=YES
# End SUBSYSTEM ESP
#######################



#######################
# Start SUBSYSTEM WEB
[SUBSYSTEM::WEB]
INIT_OBJ_FILES = \
		web_server/web_server.o
ADD_OBJ_FILES = \
		web_server/http.o \
		web_server/calls.o \
		web_server/tls.o \
		web_server/tlscert.o \
		web_server/pam.o
REQUIRED_SUBSYSTEMS = ESP EXT_LIB_GNUTLS EXT_LIB_PAM SMBCALLS
# End SUBSYSTEM WEB
#######################
