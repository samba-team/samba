##################
[SUBSYSTEM::brlock_ctdb]
PUBLIC_DEPENDENCIES = ctdb

brlock_ctdb_OBJ_FILES = $(ctdbsrcdir)/brlock_ctdb.o

##################
[SUBSYSTEM::opendb_ctdb]
PUBLIC_DEPENDENCIES = ctdb

opendb_ctdb_OBJ_FILES = $(ctdbsrcdir)/opendb_ctdb.o

##################
[SUBSYSTEM::ctdb]
PUBLIC_DEPENDENCIES = TDB_WRAP LIBTALLOC LIBEVENTS

ctdb_OBJ_FILES = $(addprefix $(ctdbsrcdir)/, \
		ctdb_cluster.o \
		client/ctdb_client.o \
		common/ctdb_io.o \
		common/ctdb_ltdb.o \
		common/ctdb_message.o \
		common/ctdb_util.o)

