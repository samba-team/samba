#
#	Makefile for the Mbedthis Portable Runtime (MPR) library 
#
#	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
#

COMPILE			:= *.c 
EXPORT_OBJECTS	:= yes

include 		make.dep

ifeq 			($(BLD_HOST_UNIX),1)
PRE_DIRS		= UNIX
else
PRE_DIRS		= $(BLD_HOST_OS)
endif

POST_DIRS		= package

TARGETS			+= $(BLD_BIN_DIR)/libmpr$(BLD_LIB)

compileExtra: $(TARGETS)

#
#	Build the mpr libraries
#
$(BLD_BIN_DIR)/libmpr$(BLD_LIB): files \
	$(shell BLD_OBJ=$(BLD_OBJ) \; BLD_OBJ_DIR=$(BLD_OBJ_DIR) \; \
		eval echo `cat files`)
	@bld --library $(BLD_BIN_DIR)/libmpr \
		--objectsDir $(BLD_OBJ_DIR) --objectList files

cleanExtra:
	@echo "rm -f $(TARGETS)" | $(BLDOUT)
	@rm -f $(TARGETS)
	@rm -f $(BLD_BIN_DIR)/libmpr.*

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
