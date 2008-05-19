#######################
# Start SUBSYSTEM MPR
[SUBSYSTEM::MPR]
# End SUBSYSTEM MPR
#######################

MPR_OBJ_FILES = $(addprefix $(appwebsrcdir)/mpr/, miniMpr.o var.o)

#######################
# Start SUBSYSTEM EJS
[SUBSYSTEM::EJS]
PUBLIC_DEPENDENCIES = MPR
# End SUBSYSTEM EJS
#######################

EJS_OBJ_FILES = $(addprefix $(appwebsrcdir)/ejs/, ejsLib.o ejsLex.o ejsParser.o ejsProcs.o)

#######################
# Start SUBSYSTEM ESP
[SUBSYSTEM::ESP]
PUBLIC_DEPENDENCIES = EJS
# End SUBSYSTEM ESP
#######################

ESP_OBJ_FILES = $(addprefix $(appwebsrcdir)/esp/, esp.o espProcs.o)
