##################
[MODULE::brlock_ctdb]
SUBSYSTEM = ntvfs_common
OBJ_FILES = brlock_ctdb.o

##################
[MODULE::ctdb_tcp]
SUBSYSTEM = CLUSTER
OBJ_FILES = \
		tcp/tcp_init.o \
		tcp/tcp_io.o \
		tcp/tcp_connect.o

##################
[MODULE::ctdb]
SUBSYSTEM = CLUSTER
OBJ_FILES = \
		ctdb_cluster.o \
		common/ctdb.o \
		common/ctdb_call.o \
		common/ctdb_message.o \
		common/ctdb_ltdb.o \
		common/ctdb_util.o
PRIVATE_DEPENDENCIES = ctdb_tcp
PUBLIC_DEPENDENCIES = LIBTDB LIBTALLOC
