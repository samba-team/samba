#######################
# Start SUBSYSTEM EJS
[SUBSYSTEM::EJS]
ADD_OBJ_FILES = \
		lib/appweb/ejs/ejsLib.o  \
		lib/appweb/ejs/ejsLex.o \
		lib/appweb/ejs/ejsParser.o \
		lib/appweb/ejs/ejsProcs.o \
		lib/appweb/ejs/miniMpr.o \
		lib/appweb/ejs/var.o
NOPROTO=YES
# End SUBSYSTEM EJS
#######################

#######################
# Start SUBSYSTEM ESP
[SUBSYSTEM::ESP]
ADD_OBJ_FILES = \
		lib/appweb/esp/esp.o  \
		lib/appweb/esp/espProcs.o
REQUIRED_SUBSYSTEMS = EJS
NOPROTO=YES
# End SUBSYSTEM ESP
#######################
