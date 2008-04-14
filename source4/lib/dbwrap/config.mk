[SUBSYSTEM::LIBDBWRAP]
PUBLIC_DEPENDENCIES = \
		LIBTDB ctdb

LIBDBWRAP_OBJ_FILES = $(addprefix lib/dbwrap/, dbwrap.o dbwrap_tdb.o dbwrap_ctdb.o)

