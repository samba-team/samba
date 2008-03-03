##################
[SUBSYSTEM::brlock_ctdb]
PUBLIC_DEPENDENCIES = ctdb

brlock_ctdb_OBJ_FILES = brlock_ctdb.o

##################
[SUBSYSTEM::opendb_ctdb]
PUBLIC_DEPENDENCIES = ctdb

opendb_ctdb_OBJ_FILES = opendb_ctdb.o

##################
[SUBSYSTEM::ctdb]
PUBLIC_DEPENDENCIES = TDB_WRAP LIBTALLOC

ctdb_OBJ_FILES = $(addprefix cluster/ctdb/, \
		ctdb_cluster.o \
		client/ctdb_client.o \
		common/ctdb_io.o \
		common/ctdb_ltdb.o \
		common/ctdb_message.o \
		common/ctdb_util.o)

