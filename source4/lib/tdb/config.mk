################################################
# Start SUBSYSTEM LIBTDB
[LIBRARY::LIBTDB]
OUTPUT_TYPE = STATIC_LIBRARY
OBJ_FILES = \
	common/tdb.o common/dump.o common/io.o common/lock.o \
	common/open.o common/traverse.o common/freelist.o \
	common/error.o common/transaction.o
CFLAGS = -Ilib/tdb/include
#
# End SUBSYSTEM ldb
################################################

################################################
# Start BINARY tdbtool
[BINARY::tdbtool]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/tdbtool.o
PRIVATE_DEPENDENCIES = \
		LIBTDB
# End BINARY tdbtool
################################################

################################################
# Start BINARY tdbtorture
[BINARY::tdbtorture]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/tdbtorture.o
PRIVATE_DEPENDENCIES = \
		LIBTDB
# End BINARY tdbtorture
################################################

################################################
# Start BINARY tdbdump
[BINARY::tdbdump]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/tdbdump.o
PRIVATE_DEPENDENCIES = \
		LIBTDB
# End BINARY tdbdump
################################################

################################################
# Start BINARY tdbbackup
[BINARY::tdbbackup]
INSTALLDIR = BINDIR
OBJ_FILES= \
		tools/tdbbackup.o
PRIVATE_DEPENDENCIES = \
		LIBTDB
# End BINARY tdbbackup
################################################
