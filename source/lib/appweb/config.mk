#######################
# Start SUBSYSTEM MPR
[SUBSYSTEM::MPR]
OBJ_FILES = \
		mpr/miniMpr.o \
		mpr/var.o
NOPROTO=YES
# End SUBSYSTEM MPR
#######################


#######################
# Start SUBSYSTEM EJS
[SUBSYSTEM::EJS]
OBJ_FILES = \
		ejs/ejsLib.o  \
		ejs/ejsLex.o \
		ejs/ejsParser.o \
		ejs/ejsProcs.o
REQUIRED_SUBSYSTEMS = MPR
NOPROTO=YES
# End SUBSYSTEM EJS
#######################

#######################
# Start SUBSYSTEM ESP
[SUBSYSTEM::ESP]
OBJ_FILES = \
		esp/esp.o  \
		esp/espProcs.o
REQUIRED_SUBSYSTEMS = EJS
NOPROTO=YES
# End SUBSYSTEM ESP
#######################
