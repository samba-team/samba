[SUBSYSTEM::LIBCOM]
INIT_OBJ_FILES = \
		lib/com/tables.o \
		lib/com/rot.o \
		lib/com/main.o

[MODULE::com_simple]
SUBSYSTEM = LIBCOM
INIT_OBJ_FILES = lib/com/classes/simple.o
INIT_FUNCTION = com_simple_init
