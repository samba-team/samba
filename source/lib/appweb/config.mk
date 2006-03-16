#######################
# Start SUBSYSTEM MPR
[SUBSYSTEM::MPR]
OBJ_FILES = \
		mpr/miniMpr.o \
		mpr/var.o
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
# End SUBSYSTEM EJS
#######################

#######################
# Start SUBSYSTEM ESP
[SUBSYSTEM::ESP]
OBJ_FILES = \
		esp/esp.o  \
		esp/espProcs.o
REQUIRED_SUBSYSTEMS = EJS
# End SUBSYSTEM ESP
#######################
