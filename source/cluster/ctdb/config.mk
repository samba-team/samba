##################
[SUBSYSTEM::brlock_ctdb]
OBJ_FILES = brlock_ctdb.o

##################
[SUBSYSTEM::opendb_ctdb]
OBJ_FILES = opendb_ctdb.o

##################
[SUBSYSTEM::ctdb]
OBJ_FILES = \
		ctdb_cluster.o \
		client/ctdb_client.o \
		common/ctdb_io.o \
		common/ctdb_ltdb.o \
		common/ctdb_message.o \
		common/ctdb_util.o
PUBLIC_DEPENDENCIES = LIBTDB LIBTALLOC
