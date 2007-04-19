##################
[SUBSYSTEM::brlock_ctdb]
OBJ_FILES = brlock_ctdb.o

##################
[SUBSYSTEM::opendb_ctdb]
OBJ_FILES = opendb_ctdb.o

##################
[SUBSYSTEM::ctdb_tcp]
OBJ_FILES = \
		tcp/tcp_init.o \
		tcp/tcp_io.o \
		tcp/tcp_connect.o

##################
[SUBSYSTEM::ctdb]
INIT_FUNCTION = server_service_ctdbd_init
OBJ_FILES = \
		ctdb_cluster.o \
		common/ctdb.o \
		common/ctdb_call.o \
		common/ctdb_message.o \
		common/ctdb_ltdb.o \
		common/ctdb_util.o \
		common/ctdb_io.o \
		common/ctdb_client.o \
		common/ctdb_daemon.o
PUBLIC_DEPENDENCIES = LIBTDB LIBTALLOC
PRIVATE_DEPENDENCIES = ctdb_tcp
