[SUBSYSTEM::LIBDBWRAP]
OBJ_FILES = dbwrap.o \
		dbwrap_tdb.o \
		dbwrap_ctdb.o
PUBLIC_DEPENDENCIES = \
		LIBTDB ctdb
