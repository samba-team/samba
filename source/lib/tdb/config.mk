################################################
# Start SUBSYSTEM LIBTDB
[SUBSYSTEM::LIBTDB]
INIT_OBJ_FILES = \
		lib/tdb/tdb.o
ADD_OBJ_FILES = \
		lib/tdb/tdbutil.o \
		lib/tdb/spinlock.o
#
# End SUBSYSTEM LIBLDB
################################################

################################################
# Start LIBRARY LIBTDB
[LIBRARY::libtdb]
MAJOR_VERSION = 0
MINOR_VERSION = 0
RELEASE_VERSION = 1
REQUIRED_SUBSYSTEMS = \
		LIBTDB
#
# End LIBRARY LIBLDB
################################################
