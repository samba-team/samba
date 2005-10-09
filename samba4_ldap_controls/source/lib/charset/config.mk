################################################
# Start SUBSYSTEM CHARSET
[SUBSYSTEM::CHARSET]
INIT_OBJ_FILES = \
		lib/charset/iconv.o
ADD_OBJ_FILES = \
		lib/charset/charcnv.o
REQUIRED_SUBSYSTEMS = EXT_LIB_ICONV
# End SUBSYSTEM CHARSET
################################################
