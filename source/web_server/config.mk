# web server subsystem

#######################
# Start SUBSYSTEM EJS
[SUBSYSTEM::EJS]
ADD_OBJ_FILES = \
		web_server/ejs/ejs.o  \
		web_server/ejs/ejsLex.o \
		web_server/ejs/ejsParser.o \
		web_server/ejs/ejsProcs.o \
		web_server/ejs/miniMpr.o \
		web_server/ejs/var.o
NOPROTO=YES
# End SUBSYSTEM EJS
#######################

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
		web_server/http.o
REQUIRED_SUBSYSTEMS = ESP
# End SUBSYSTEM WEB
#######################
