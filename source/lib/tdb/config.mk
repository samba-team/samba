################################################
# Start SUBSYSTEM LIBTDB
[LIBRARY::LIBTDB]
OUTPUT_TYPE = STATIC_LIBRARY
CFLAGS = -Ilib/tdb/include
#
# End SUBSYSTEM ldb
################################################

LIBTDB_OBJ_FILES = $(addprefix lib/tdb/common/, \
	tdb.o dump.o io.o lock.o \
	open.o traverse.o freelist.o \
	error.o transaction.o)

################################################
# Start BINARY tdbtool
[BINARY::tdbtool]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBTDB
# End BINARY tdbtool
################################################

tdbtool_OBJ_FILES = lib/tdb/tools/tdbtool.o

################################################
# Start BINARY tdbtorture
[BINARY::tdbtorture]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBTDB
# End BINARY tdbtorture
################################################

tdbtorture_OBJ_FILES = lib/tdb/tools/tdbtorture.o

################################################
# Start BINARY tdbdump
[BINARY::tdbdump]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBTDB
# End BINARY tdbdump
################################################

tdbdump_OBJ_FILES = lib/tdb/tools/tdbdump.o

################################################
# Start BINARY tdbbackup
[BINARY::tdbbackup]
INSTALLDIR = BINDIR
PRIVATE_DEPENDENCIES = \
		LIBTDB
# End BINARY tdbbackup
################################################

tdbbackup_OBJ_FILES = lib/tdb/tools/tdbbackup.o
