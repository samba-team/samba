#
#	Makefile for Embedded Javascript (EJS) 
#
#	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
#

#
#	Ejs may be linked into shared handlers so we must build the objects both
#	shared and static if --shared was specified to configure.
#
COMPILE			:= *.c
EXPORT_OBJECTS	:= yes
PRE_DIRS		:= classes system db
MAKE_IFLAGS		:= -I../mpr -I../exml

include 		make.dep

ifeq 			($(BLD_PRODUCT),ejs)
POST_DIRS		:= package
endif

ifeq 			($(BLD_FEATURE_TEST),1)
POST_DIRS		+= test
endif

ifeq 			($(BLD_FEATURE_EJS_DB),1)
LIBS			+= sqlite
endif

TARGETS			+= $(BLD_BIN_DIR)/libejs$(BLD_LIB)
TARGETS			+= $(BLD_BIN_DIR)/ejs$(BLD_EXE)

ifeq 			($(BLD_FEATURE_EJS),1)
compileExtra: $(TARGETS)
endif

$(BLD_BIN_DIR)/libejs$(BLD_LIB): files \
	$(shell BLD_OBJ=$(BLD_OBJ) \; BLD_OBJ_DIR=$(BLD_OBJ_DIR) \; \
		eval echo `cat files`)
	@bld --library $(BLD_BIN_DIR)/libejs \
		--objectsDir $(BLD_OBJ_DIR) --objectList files \
		--libs "exml mpr $(LIBS)"

$(BLD_BIN_DIR)/ejs$(BLD_EXE): $(BLD_BIN_DIR)/libejs$(BLD_LIB) \
		$(BLD_BIN_DIR)/libmpr$(BLD_LIB) \
		$(BLD_BIN_DIR)/libejs$(BLD_LIB) $(FILES)
	@bld --executable $(BLD_BIN_DIR)/ejs$(BLD_EXE) \
		--rpath "$(BLD_PREFIX)/bin" \
		--preferStatic --smartLibs "ejs exml mpr $(LIBS)" \
		--objectsDir $(BLD_OBJ_DIR) \
		--objects "$(BLD_OBJ_DIR)/ejsCmd$(BLD_OBJ)"

cleanExtra:
	@echo "rm -f $(TARGETS)" | $(BLDOUT)
	@rm -f $(TARGETS)
	@rm -f $(BLD_BIN_DIR)/libejs.*

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
