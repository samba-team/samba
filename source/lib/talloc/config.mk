################################################
# Start SUBSYSTEM LIBTALLOC
[SUBSYSTEM::LIBTALLOC]
INIT_OBJ_FILES = \
		lib/talloc/talloc.o
REQUIRED_SUBSYSTEMS = \
		LIBREPLACE
NOPROTO = YES
#
# End SUBSYSTEM LIBTALLOC
################################################

################################################
# Start LIBRARY LIBTALLOC
[LIBRARY::libtalloc]
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
REQUIRED_SUBSYSTEMS = \
		LIBTALLOC
#
# End LIBRARY LIBTALLOC
################################################

