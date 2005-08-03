################################################
# Start SUBSYSTEM LIBTDB
[SUBSYSTEM::LIBTDB]
INIT_OBJ_FILES = \
		lib/tdb/common/tdb.o
ADD_OBJ_FILES = \
		lib/tdb/common/tdbutil.o \
		lib/tdb/common/spinlock.o
NOPROTO=YES
REQUIRED_SUBSYSTEMS = \
		LIBREPLACE
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

################################################
# Start BINARY tdbtool
[BINARY::tdbtool]
INSTALLDIR = BINDIR
ENABLE = NO
OBJ_FILES= \
		lib/tdb/tools/tdbtool.o
REQUIRED_SUBSYSTEMS = \
		LIBTDB
# End BINARY tdbtool
################################################

################################################
# Start BINARY tdbtorture
[BINARY::tdbtorture]
INSTALLDIR = BINDIR
OBJ_FILES= \
		lib/tdb/tools/tdbtorture.o
REQUIRED_SUBSYSTEMS = \
		LIBTDB
# End BINARY tdbtorture
################################################

################################################
# Start BINARY tdbdump
[BINARY::tdbdump]
INSTALLDIR = BINDIR
OBJ_FILES= \
		lib/tdb/tools/tdbdump.o
REQUIRED_SUBSYSTEMS = \
		LIBTDB
# End BINARY tdbdump
################################################

################################################
# Start BINARY tdbbackup
[BINARY::tdbbackup]
INSTALLDIR = BINDIR
ENABLE = NO
OBJ_FILES= \
		lib/tdb/tools/tdbbackup.o
REQUIRED_SUBSYSTEMS = \
		LIBTDB
# End BINARY tdbbackup
################################################
