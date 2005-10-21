################################################
# Start SUBSYSTEM CHARSET
[SUBSYSTEM::CHARSET]
INIT_OBJ_FILES = \
		iconv.o
ADD_OBJ_FILES = \
		charcnv.o
REQUIRED_SUBSYSTEMS = EXT_LIB_ICONV
# End SUBSYSTEM CHARSET
################################################
