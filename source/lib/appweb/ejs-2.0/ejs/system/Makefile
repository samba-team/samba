#
#	Makefile to build the EJS Object Model
#
#	Copyright (c) Mbedthis Software LLC, 2003-2006. All Rights Reserved.
#

COMPILE			:= *.c
EXPORT_OBJECTS	:= yes
MAKE_IFLAGS		:= -I.. -I../../mpr -I../../exml

include 	make.dep

ifeq 			($(BLD_HOST_UNIX),1)
PRE_DIRS		 = UNIX
else
PRE_DIRS		 = $(BLD_HOST_OS)
endif

compileExtra: .updated

.updated: $(FILES)
	@touch .updated

## Local variables:
## tab-width: 4
## End:
## vim: tw=78 sw=4 ts=4
