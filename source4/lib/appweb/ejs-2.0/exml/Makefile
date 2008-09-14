#
#	Makefile for Embedded XML (EXML)
#
#	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
#

#
#	EXML may be linked into shared handlers so we must build the objects both
#	shared and static.
#
COMPILE			:= *.c
EXPORT_OBJECTS	:= yes
MAKE_IFLAGS		:= -I../mpr

include 		make.dep

ifeq 			($(BLD_FEATURE_TEST),1)
POST_DIRS		:= test
endif

TARGETS			+= $(BLD_BIN_DIR)/libexml$(BLD_LIB)

ifeq 			($(BLD_FEATURE_XML),1)
compileExtra: $(TARGETS)
endif

# MOB -- remove when FEATURE_XML is defined
compileExtra: $(TARGETS)

$(BLD_BIN_DIR)/libexml$(BLD_LIB): $(FILES)
	@bld --library $(BLD_BIN_DIR)/libexml \
		--objectsDir $(BLD_OBJ_DIR) --objectList files --libs mpr

cleanExtra:
	@echo "rm -f $(TARGETS)" | $(BLDOUT)
	@rm -f $(TARGETS)
	@rm -f $(BLD_BIN_DIR)/libexml.*

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
