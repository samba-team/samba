################################################
# Start SUBSYSTEM LIBTDB
[SUBSYSTEM::LIBTDB]
INIT_OBJ_FILES = \
		common/tdb.o
ADD_OBJ_FILES = common/dump.o common/io.o common/lock.o \
	common/open.o common/traverse.o common/freelist.o \
	common/error.o common/transaction.o common/tdbutil.o
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
		tools/tdbtool.o
REQUIRED_SUBSYSTEMS = \
		LIBTDB
# End BINARY tdbtool
################################################

################################################
# Start BINARY tdbtorture
[BINARY::tdbtorture]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/tdbtorture.o
REQUIRED_SUBSYSTEMS = \
		LIBTDB
# End BINARY tdbtorture
################################################

################################################
# Start BINARY tdbdump
[BINARY::tdbdump]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/tdbdump.o
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
		tools/tdbbackup.o
REQUIRED_SUBSYSTEMS = \
		LIBTDB
# End BINARY tdbbackup
################################################
